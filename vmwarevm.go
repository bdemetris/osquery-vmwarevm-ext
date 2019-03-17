package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/kolide/osquery-go/plugin/table"
)

// VirtualMachine is our return type
type VirtualMachine struct {
	Path   string
	UUID   string
	Serial string
}

// VMX is our return type
type VMX struct {
	UUID   string
	Serial string
}

// VMwareVMColums returns the columns that our table will return.
func VMwareVMColums() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("Path"),
		table.TextColumn("UUID"),
		table.TextColumn("Serial"),
	}
}

// VMwareVMGenerate will be called whenever the table is queried. It should return
// a full table scan.
func VMwareVMGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	vm, err := makeVirtualMachines()
	if err != nil {
		return nil, err
	}

	var values []map[string]string

	for _, element := range vm {
		j, _ := json.Marshal(element)
		m := make(map[string]string)
		err := json.Unmarshal(j, &m)
		if err != nil {
			return nil, err
		}
		values = append(values, m)

	}

	return values, nil
}

// makeVirtualMachines compiles a slice of VirtualMachines
func makeVirtualMachines() ([]VirtualMachine, error) {
	v, err := getVMPathFromSpotlight()
	if err != nil {
		return nil, err
	}

	var vms []VirtualMachine

	for _, element := range v {
		if (VirtualMachine{}) != element {
			x, err := parseVMX(element.Path)
			if err != nil {
				return nil, err
			}
			vms = append(vms, VirtualMachine{
				Path:   element.Path,
				UUID:   x.UUID,
				Serial: x.Serial,
			})
		}
	}
	return vms, nil
}

// getVMPathFromSpotlight populates the Path item in the VirtualMachines struct
func getVMPathFromSpotlight() ([]VirtualMachine, error) {
	cmd := exec.Command("/usr/bin/mdfind", "kMDItemContentType == 'com.vmware.vm-package'")

	o, err := cmd.Output()
	if err != nil {
		return []VirtualMachine{}, nil
	}

	var vms []VirtualMachine

	for _, element := range strings.Split(string(o), "\n") {
		path, err := getVMXPath(element)
		if err != nil {
			return nil, err
		}
		vm := VirtualMachine{
			Path: path,
		}
		vms = append(vms, vm)
	}

	return vms, nil
}

// getVMXPath takes a folder path and returns the full path to a vmx file
func getVMXPath(folderPath string) (string, error) {

	var files []string
	err := filepath.Walk(folderPath, func(path string, info os.FileInfo, err error) error {
		files = append(files, path)
		return nil
	})
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if filepath.Ext(file) == ".vmx" {
			return file, nil
		}
	}

	return "", nil
}

// parseVMX takes VirtualMachine.Path and returns the complete VirtualMachine type
func parseVMX(filePath string) (VMX, error) {

	uuidMatch := regexp.MustCompile(`(?m)^uuid.bios = "(.+)"$`)
	serialMatch := regexp.MustCompile(`(?m)^serialNumber = "(.+)"$`)

	data, err := ioutil.ReadFile(filePath)
	if err != nil {
		return VMX{}, nil
	}

	u := uuidMatch.FindStringSubmatch(string(data))
	s := serialMatch.FindStringSubmatch(string(data))

	if len(s) > 0 {
		s = []string{s[1]}
	} else {
		s = []string{""}
	}

	if len(u) > 0 {
		u = []string{u[1]}
	} else {
		u = []string{""}
	}

	vmx := VMX{
		UUID:   u[0],
		Serial: s[0],
	}

	return vmx, nil
}
