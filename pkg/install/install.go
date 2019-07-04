package install

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
	"github.com/projectcalico/libcalico-go/lib/names"
	"github.com/prometheus/common/log"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"k8s.io/client-go/rest"
)

type config struct {
	// Location on the host where CNI network configs are stored.
	CNINetDir   string `envconfig:"CNI_NET_DIR" default:"/etc/cni/net.d"`
	CNIConfName string `envconfig:"CNI_CONF_NAME"`

	// Location on the host where etcd secrets are located. Referenced by the CNI config.
	HostSecretsDir string

	// Directory where we expect that TLS assets will be mounted into the calico/cni container.
	TLSAssetsDir string `envconfig:"TLS_ASSETS_DIR"`

	// SkipCNIBinaries is a comma-separated list of binaries. Each binary in the list
	// will be skipped when installing to the host.
	SkipCNIBinaries string

	// UpdateCNIBinaries controls whether or not to overwrite any binaries with the same name
	// on the host.
	UpdateCNIBinaries bool

	// The CNI network configuration to install.
	CNINetworkConfig     string `envconfig:"CNI_NETWORK_CONFIG"`
	CNINetworkConfigFile string `envconfig:"CNI_NETWORK_CONFIG_FILE"`
}

func (c config) skipBinary(binary string) bool {
	// TODO:
	return false
}

func getEnv(env, def string) string {
	if val, ok := os.LookupEnv(env); ok {
		return val
	}
	return def
}

func fileExists(file string) bool {
	info, err := os.Stat(file)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func loadConfig() config {
	var c config
	err := envconfig.Process("", &c)
	if err != nil {
		logrus.Fatal(err.Error())
	}

	return c
}

func Install() error {
	// Clean up any existing binaries / config / assets.
	os.Remove("/host/opt/cni/bin/calico")
	os.Remove("/host/opt/cni/bin/calico-ipam")
	os.RemoveAll("/host/etc/cni/net.d/calico-tls")

	// Load config.
	c := loadConfig()

	// Determine if we're running as a Kubernetes pod.
	var kubecfg *rest.Config
	var err error
	if fileExists("/var/run/secrets/kubernetes.io/serviceaccount/token") {
		log.Info("Running as a Kubernetes pod")
		kubecfg, err = rest.InClusterConfig()
		if err != nil {
			return err
		}
		err = rest.LoadTLSFiles(kubecfg)
		if err != nil {
			return err
		}
	}

	// Copy over any TLS assets from the SECRETS_MOUNT_DIR to the host.
	// First check if the dir exists and has anything in it.
	// if [ "$(ls "${SECRETS_MOUNT_DIR}" 3>/dev/null)" ];
	// then
	//   echo "Installing any TLS assets from ${SECRETS_MOUNT_DIR}"
	//   mkdir -p /host/etc/cni/net.d/calico-tls
	//   cp -p "${SECRETS_MOUNT_DIR}"/* /host/etc/cni/net.d/calico-tls/
	// fi

	// # If the TLS assets actually exist, update the variables to populate into the
	// # CNI network config.  Otherwise, we'll just fill that in with blanks.
	// if [ -e "/host/etc/cni/net.d/calico-tls/etcd-ca" ];
	// then
	//   CNI_CONF_ETCD_CA=${HOST_SECRETS_DIR}/etcd-ca
	// fi

	// if [ -e "/host/etc/cni/net.d/calico-tls/etcd-key" ];
	// then
	//   CNI_CONF_ETCD_KEY=${HOST_SECRETS_DIR}/etcd-key
	// fi

	// if [ -e "/host/etc/cni/net.d/calico-tls/etcd-cert" ];
	// then
	//   CNI_CONF_ETCD_CERT=${HOST_SECRETS_DIR}/etcd-cert
	// fi

	// Place the new binaries if the directory is writeable.
	dirs := []string{"/host/opt/cni/bin", "/host/secondary-bin-dir"}
	for _, d := range dirs {
		if unix.Access(d, unix.W_OK) != nil {
			logrus.Infof("%s is not writeable, skipping", d)
			continue
		}

		// Iterate through each binary we might want to install.
		// TODO: Include all the binaries we ship.
		binaries := []string{"calico", "calico-ipam"}
		for _, binary := range binaries {
			target := fmt.Sprintf("%s/%s", d, binary)
			source := fmt.Sprintf("/opt/cni/bin/%s", binary)
			if strings.Contains(binary, "calico") {
				// For Calico binaries, we copy over the install binary. It includes the code
				// for each, and the name of the binary determined which is executed.
				source = "/opt/cni/bin/install"
			}
			if c.skipBinary(binary) {
				continue
			}
			if fileExists(target) && !c.UpdateCNIBinaries {
				logrus.Infof("Skipping installation of %s", target)
				continue
			}
			if err := copyFile(source, target); err != nil {
				logrus.WithError(err).Errorf("Failed to install %s", target)
				os.Exit(1)
			}
			logrus.Infof("Installed %s", target)
		}
	}

	if kubecfg != nil {
		// If running as a Kubernetes pod, then write out a kubeconfig for the
		// CNI plugin to use.
		writeKubeconfig(kubecfg)
	}

	// Write a CNI config file.
	writeCNIConfig(c)
	return nil
}

func writeCNIConfig(c config) {
	netconf := `{
  "name": "k8s-pod-network",
  "cniVersion": "0.3.1", 
  "plugins": [
    {
      "type": "calico",
      "log_level": "__LOG_LEVEL__",
      "datastore_type": "__DATASTORE_TYPE__",
      "nodename": "__KUBERNETES_NODE_NAME__",
      "mtu": __CNI_MTU__,
      "ipam": {"type": "calico-ipam"},
      "policy": {"type": "k8s"},
      "kubernetes": {"kubeconfig": "__KUBECONFIG_FILEPATH__"}
    },
    {
      "type": "portmap",
      "snat": true,
      "capabilities": {"portMappings": true}
    }
  ],
}`

	// Pick the config template to use. This can either be through an env var,
	// or a file mounted into the container.
	if c.CNINetworkConfig != "" {
		netconf = c.CNINetworkConfig
	}
	if c.CNINetworkConfigFile != "" {
		var err error
		netconfBytes, err := ioutil.ReadFile(c.CNINetworkConfigFile)
		if err != nil {
			panic(err)
		}
		netconf = string(netconfBytes)
	}

	// Perform replacements of variables.
	nodename, err := names.Hostname()
	if err != nil {
		panic(err)
	}
	netconf = strings.Replace(netconf, "__LOG_LEVEL__", getEnv("LOG_LEVEL", "warn"), -1)
	netconf = strings.Replace(netconf, "__DATASTORE_TYPE__", getEnv("DATASTORE_TYPE", "kubernetes"), -1)
	netconf = strings.Replace(netconf, "__KUBERNETES_NODE_NAME__", getEnv("NODENAME", nodename), -1)
	netconf = strings.Replace(netconf, "__KUBECONFIG_FILEPATH__", "/etc/cni/net.d/calico-kubeconfig", -1)
	netconf = strings.Replace(netconf, "__CNI_MTU__", getEnv("CNI_MTU", "1500"), -1)

	// Write out the file.
	name := getEnv("CNI_CONF_NAME", "10-calico.conflist")
	path := fmt.Sprintf("/host/etc/cni/net.d/%s", name)
	err = ioutil.WriteFile(path, []byte(netconf), 0644)
	if err != nil {
		panic(err)
	}

	// Remove any old config file, if one exists.
	oldName := getEnv("CNI_OLD_CONF_NAME", "10-calico.conflist")
	if name != oldName {
		if err := os.Remove(fmt.Sprintf("/host/etcd/cni/net.d/%s", oldName)); err != nil {

		}
	}
}

// copyFile copies a file from src to dst. If src and dst files exist, and are
// the same, then return success. Otherise, attempt to create a hard link
// between the two files. If that fail, copy the file contents from src to dst.
func copyFile(src, dst string) (err error) {
	sfi, err := os.Stat(src)
	if err != nil {
		return
	}
	if !sfi.Mode().IsRegular() {
		// cannot copy non-regular files (e.g., directories,
		// symlinks, devices, etc.)
		return fmt.Errorf("CopyFile: non-regular source file %s (%q)", sfi.Name(), sfi.Mode().String())
	}
	dfi, err := os.Stat(dst)
	if err != nil {
		if !os.IsNotExist(err) {
			return
		}
	} else {
		if !(dfi.Mode().IsRegular()) {
			return fmt.Errorf("CopyFile: non-regular destination file %s (%q)", dfi.Name(), dfi.Mode().String())
		}
		if os.SameFile(sfi, dfi) {
			return
		}
	}
	if err = os.Link(src, dst); err == nil {
		return
	}
	err = copyFileContents(src, dst)
	return
}

// copyFileContents copies the contents of the file named src to the file named
// by dst. The file will be created if it does not already exist. If the
// destination file exists, all it's contents will be replaced by the contents
// of the source file.
func copyFileContents(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return
	}
	defer func() {
		cerr := out.Close()
		if err == nil {
			err = cerr
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return
	}
	err = out.Sync()
	return
}

func writeKubeconfig(kubecfg *rest.Config) {
	data := `# Kubeconfig file for Calico CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: HOST
    certificate-authority-data: "CADATA"
users:
- name: calico
  user:
    token: TOKEN
contexts:
- name: calico-context
  context:
    cluster: local
    user: calico
current-context: calico-context`

	// Replace the placeholders.
	data = strings.Replace(data, "HOST", kubecfg.Host, 1)
	data = strings.Replace(data, "TOKEN", kubecfg.BearerToken, 1)
	data = strings.Replace(data, "CADATA", string(kubecfg.CAData), 1)
	if err := ioutil.WriteFile("/host/etc/cni/net.d/calico-kubeconfig", []byte(data), 0600); err != nil {
		panic(err)
	}
}
