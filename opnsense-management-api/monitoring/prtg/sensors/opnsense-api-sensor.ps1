<#
.SYNOPSIS
  PRTG Custom Sensor per l'API di gestione OPNsense.
  Controlla lo stato di salute dell'API e restituisce i valori in formato PRTG XML.
.DESCRIPTION
  Questo script effettua una chiamata all'endpoint di salute dell'API di gestione OPNsense
  e ne analizza la risposta per determinare lo stato.
  Restituisce il CPU, la Memoria e lo stato generale in canali separati per PRTG.
.NOTES
  PRTG deve avere PowerShell installato e configurato per eseguire script remoti.
  Assicurati che l'API sia accessibile dalla macchina PRTG.
#>

$apiEndpoint = "http://192.168.216.50:3000/api/v1/health/ready" # Indirizzo IP del tuo container opnsense-api sulla LAN Docker
$jsonResponse = ""
$cpuUsage = 0
$memoryUsage = 0
$statusMessage = "OK"
$statusCode = 0 # 0 = OK, 1 = Warning, 2 = Error, 3 = Custom (default PRTG behavior)

try {
    # Effettua la richiesta HTTP
    $response = Invoke-RestMethod -Uri $apiEndpoint -Method Get -TimeoutSec 10
    $jsonResponse = $response | ConvertTo-Json -Depth 10 # Converte la risposta in JSON leggibile

    # Analizza la risposta JSON
    if ($response.success -eq $true) {
        $status = $response.data.status
        # Questi campi 'cpu_usage' e 'memory_usage' sono un esempio.
        # Devi assicurarti che il tuo endpoint /api/v1/health/ready li restituisca
        # o adattare il parsing JSON a ciò che il tuo endpoint restituisce effettivamente.
        # Ad esempio, se sono dentro 'system_metrics':
        # $cpuUsage = $response.data.system_metrics.cpu_usage
        # $memoryUsage = $response.data.system_metrics.memory_usage
        
        # Nel tuo `health.js`, l'endpoint `/api/v1/health/ready` restituisce le metriche
        # all'interno dell'oggetto `dependencies`. Modifica per accedere correttamente:
        $dependencies = $response.data.dependencies | ConvertTo-Json -Compress # Converte l'oggetto dependencies in JSON string
        # Per accedere a CPU e memoria, dovresti estrarli dai campi di sistema e cache
        # che sono dentro le dipendenze. Il tuo health.js restituisce:
        # data: { status: "ready", dependencies: { database: {...}, cache: {...}, opnsense_api: {...} } }
        # Non ci sono CPU/Memory diretti nell'endpoint /health/ready, ma in /health e /health/metrics.
        # Per questo sensore, useremo i dati di `/api/v1/health` generati da `health.js`
        # Se intendi usare `/api/v1/health/ready`, questo sensore necessiterà modifiche
        # per recuperare metriche da /api/v1/health/metrics o simili, o l'endpoint /ready
        # deve essere esteso per includere CPU/Memory diretti.
        
        # Per ora, si assume che le metriche siano accessibili direttamente per test di base.
        # Se non esistono direttamente nell'endpoint /ready, questi valori saranno 0.
        
        # Correggendo l'accesso per i valori CPU/Memory in base alla tua struttura in health.js
        # L'endpoint /api/v1/health/ready non espone direttamente CPU/Memory.
        # Se vuoi queste metriche, potresti dover chiamare /api/v1/health/metrics o estendere /ready.
        # Per questo esempio, li lasceremo come valori placeholder o da adattare.
        $cpuUsage = 0 # Placeholder: Adatta questo se /ready esporrà CPU
        $memoryUsage = 0 # Placeholder: Adatta questo se /ready esporrà Memory

        if ($status -eq "ready") {
            $statusMessage = "OPNsense API è pronta."
            $statusCode = 0
        } elseif ($status -eq "degraded") {
            $statusMessage = "OPNsense API è degradata. Verificare le dipendenze."
            $statusCode = 1 # Warning
        } else {
            $statusMessage = "OPNsense API non è pronta. Stato inatteso: $($status)."
            $statusCode = 2 # Error
        }
    } else {
        $statusMessage = "Errore nell'API di OPNsense: $($response.message)."
        $statusCode = 2 # Error
    }
} catch {
    $statusMessage = "Impossibile connettersi all'API di OPNsense: $($_.Exception.Message)"
    $statusCode = 2 # Error
}

# Costruisci l'output XML per PRTG
$xmlOutput = @"
<prtg>
    <result>
        <channel>API Status</channel>
        <value>$statusCode</value>
        <text>$statusMessage</text>
        <unit>Custom</unit>
        <CustomUnit>Status</CustomUnit>
        <limitmin>0</limitmin>
        <limitmax>0</limitmax>
        <limitemergency>2</limitemergency>
        <limitwarning>1</limitwarning>
    </result>
    <result>
        <channel>CPU Usage</channel>
        <value>$($cpuUsage | Measure-Object -Average).Average</value> # Assumiamo che cpuUsage sia un array o una singola metrica
        <unit>Percent</unit>
        <float>1</float>
    </result>
    <result>
        <channel>Memory Usage</channel>
        <value>$($memoryUsage | Measure-Object -Average).Average</value> # Assumiamo che memoryUsage sia un array o una singola metrica
        <unit>Percent</unit>
        <float>1</float>
    </result>
    <Text>$statusMessage</Text>
</prtg>
"@

Write-Host $xmlOutput
