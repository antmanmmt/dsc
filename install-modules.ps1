Set-ExecutionPolicy -ExecutionPolicy Bypass -Force

  ## install nuget provider
 install-packageprovider -name nuget -minimumversion 2.8.5.201 -force

 ## trust the psgallery
 set-psrepository -name "psgallery" -installationpolicy trusted

 ## installed required packages (note that these must be available int he psgallery)
 install-module xstorage -force
 Install-Module -Name xWebAdministration -Force
 install-module xwebadministration -force
 install-module xnetworking -force
 install-module cntfsaccesscontrol -force
 install-module xPSDesiredStateConfiguration -force
 install-module NetworkingDsc -force
