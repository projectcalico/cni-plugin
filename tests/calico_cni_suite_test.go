//  Copyright (c) 2016,2018 Tigera, Inc. All rights reserved.

package main_test

import (
	"fmt"
	"os"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"testing"

	"github.com/onsi/ginkgo/reporters"
)

func TestCalicoCni(t *testing.T) {
	RegisterFailHandler(Fail)
	file := fmt.Sprintf("../report/cni_suite_%s.xml", os.Getenv("DATASTORE_TYPE"))
	junitReporter := reporters.NewJUnitReporter(file)
	RunSpecsWithDefaultAndCustomReporters(t, "Calico CNI Suite", []Reporter{junitReporter})
}
