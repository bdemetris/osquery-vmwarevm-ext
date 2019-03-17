## vmwarevm.ext

an osquery extension that enumerates vmware vm's present on a macos device.  this uses a spotlight search for `kMDItemContentType == 'com.vmware.vm-package'`

the resulting table includes:

`Path`: path to the vmx file
`UUID`: is the `uuid.bios` of the vm which is by default is serial
`Serial`: is not default, but we will report it if the user assigns one to the vm.

## build

the project uses deps

clone the project and then `dep init`, then you can just `make deps` and then `make build`