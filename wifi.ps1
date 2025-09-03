#Que se vea asi guapo indentao aunque sea y no el chorizo de antes
$global:NombrePerfil = "RCJA"
$Perfil_Wifi='<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
        <name>RCJA</name>
        <SSIDConfig>
                <SSID>
                        <hex>52434A41</hex>
                        <name>RCJA</name>
                </SSID>
                <nonBroadcast>false</nonBroadcast>
        </SSIDConfig>
        <connectionType>ESS</connectionType>
        <connectionMode>auto</connectionMode>
        <autoSwitch>false</autoSwitch>
        <MSM>
                <security>
                        <authEncryption>
                                <authentication>WPA2</authentication>
                                <encryption>AES</encryption>
                                <useOneX>true</useOneX>
                        </authEncryption>
                        <OneX xmlns="http://www.microsoft.com/networking/OneX/v1">
                                <cacheUserData>true</cacheUserData>
                                <authMode>user</authMode>
                                <EAPConfig><EapHostConfig xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapMethod><Type xmlns="http://www.microsoft.com/provisioning/EapCommon">21</Type><VendorId xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorId><VendorType xmlns="http://www.microsoft.com/provisioning/EapCommon">0</VendorType><AuthorId xmlns="http://www.microsoft.com/provisioning/EapCommon">311</AuthorId></EapMethod><Config xmlns="http://www.microsoft.com/provisioning/EapHostConfig"><EapTtls xmlns="http://www.microsoft.com/provisioning/EapTtlsConnectionPropertiesV1"><ServerValidation><ServerNames></ServerNames><DisablePrompt>false</DisablePrompt></ServerValidation><Phase2Authentication><PAPAuthentication/></Phase2Authentication><Phase1Identity><IdentityPrivacy>false</IdentityPrivacy></Phase1Identity></EapTtls></Config></EapHostConfig></EAPConfig>
                        </OneX>
                </security>
        </MSM>
</WLANProfile>'

Function CreaPerfil {
    netsh wlan add profile filename="$env:TEMP/$global:NombreFichero"
    CompruebaPerfil
    Write-Host "Reiniciando adaptador..."
    Get-NetAdapter | Where-Object {$_.InterfaceGuid -eq "$global:ReiniciameEstaCrack"} | Restart-NetAdapter #Me la chupas tonto
    #Restart-NetAdapter -Name "Wi-Fi" 
}

Function CompruebaPerfil {
    #https://www.reddit.com/r/PowerShell/comments/ercfj1/manage_wireless_networks_setting_with_powershell/     grande este tio
    #Tengo que recorrer de esta lista todas las interfaces que son wifi porque la carpeta es Wlansvc
    $RutaInterfaces = "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\"
    $Interfaces = Get-ChildItem $RutaInterfaces | Select-Object -ExpandProperty Name
    :principal foreach ($Interfaz in $Interfaces) {
        $Perfiles = Get-ChildItem $RutaInterfaces$Interfaz | Select-Object -ExpandProperty Name #Aqui formo la ruta completa
        foreach ($Perfil in $Perfiles) {
            $PerfilXML = [xml](Get-Content $RutaInterfaces$Interfaces\$Perfil)
            Write-Host "Comparando $PerfilXML.WLANProfile.SSIDConfig.SSID.name con $global:NombrePerfil"
            if($PerfilXML.WLANProfile.SSIDConfig.SSID.name -eq $global:NombrePerfil){
                $global:PerfilWifiExiste = $true
                $global:ReiniciameEstaCrack = $Interfaz
                Write-Host "Encontrado el perfil RCJA"
                break :principal
            }
        }
    }
    Write-Host $global:PerfilWifiExiste
    if($global:PerfilWifiExiste -ne $true){ #Habra que crearte el perfil puto lila
        CreaPerfil
    }else{
        $wsh = New-Object -ComObject Wscript.Shell
        $wsh.Popup("Perfil Wifi $NombrePerfil creado",0,"OK",0 + 64)
    }

    Remove-Item -Path $env:TEMP/$global:NombreFichero  #Borro el fichero lo haya usado o no
}

#Esto creo que seria vulnerable a una carrera de condicion, si alguien consigue escribir en el fichero antes de usarlo pueden cargar un perfil distinto o podria ser incluso peor
Function CreaFichero {
    #Genero un UUID tipo 4 (el que microsoft dice que es un guid pero que como son retrasaos pos le ponen un puto nombre distinto)
    $global:NombreFichero = New-Guid  #La creo global para llamarla luego donde me salga del pijo
    if ( !(Test-Path -Path $env:TEMP/$NombreFichero) ){   #Compruebo si existe el fichero que voy a generar
        $Perfil_Wifi | Out-File -FilePath $env:TEMP/$NombreFichero
        CompruebaPerfil  #Llamo a la funcion de comprobar el perfil con netsh, bastante obvio el nombre, pero mejor documentao que encallao
    }else{
        Write-Host "Existe el fichero, vaya casualidad, genero uno nuevo"
        CreaFichero  #Me llamo recursivamente
    }
}

#La comprobacion de admin se puede hacer a nivel de script, pero, y si lanzas el script con doble click? se te abre y cierra la powershell sin poder ver el mensaje
$IsAdmin=[Security.Principal.WindowsIdentity]::GetCurrent()
$global:PerfilWifiExiste = $false #Inicializo en paso en falso payaso
If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE){
    #$wsh = New-Object -ComObject Wscript.Shell
    #$wsh.Popup("Se necesita ejecutar como administrador",0,"ERROR",0 + 16)
    $newProcess = new-object System.Diagnostics.ProcessStartInfo "powershell"
    $newProcess.Arguments = $myInvocation.MyCommand.Definition
    $newProcess.Verb = "runas"
    [System.Diagnostics.Process]::Start($newProcess)
}else{
    CreaFichero
}
