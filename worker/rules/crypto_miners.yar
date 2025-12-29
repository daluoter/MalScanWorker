rule crypto_miner {
    meta:
        description = "Detects cryptocurrency mining software"
        author = "MalScan"
        severity = "high"
    strings:
        $stratum1 = "stratum+tcp://" ascii nocase
        $stratum2 = "stratum+ssl://" ascii nocase
        $stratum3 = "stratum2+tcp://" ascii nocase
        $xmr1 = "pool.minexmr.com" ascii nocase
        $xmr2 = "xmrpool.eu" ascii nocase
        $xmr3 = "supportxmr.com" ascii nocase
        $nicehash = "nicehash.com" ascii nocase
        $ethermine = "ethermine.org" ascii nocase
        $nanopool = "nanopool.org" ascii nocase
        $monero = "pool.monero" ascii nocase
    condition:
        any of them
}

rule crypto_miner_config {
    meta:
        description = "Detects cryptocurrency miner configuration patterns"
        author = "MalScan"
        severity = "medium"
    strings:
        $wallet1 = "wallet_address" ascii nocase
        $wallet2 = "wallet=" ascii nocase
        $wallet3 = "--user=" ascii nocase
        $pool1 = "mining_pool" ascii nocase
        $pool2 = "pool_address" ascii nocase
        $pool3 = "--pool=" ascii nocase
        $worker1 = "worker_name" ascii nocase
        $worker2 = "worker_id" ascii nocase
        $worker3 = "rig_id" ascii nocase
        $pass1 = "pool_password" ascii nocase
        $pass2 = "--pass=" ascii nocase
        $threads = "--threads=" ascii nocase
        $algo1 = "cryptonight" ascii nocase
        $algo2 = "randomx" ascii nocase
        $algo3 = "ethash" ascii nocase
    condition:
        2 of them
}

rule crypto_miner_binary {
    meta:
        description = "Detects common cryptocurrency miner binary names"
        author = "MalScan"
        severity = "high"
    strings:
        $xmrig = "xmrig" ascii nocase
        $cpuminer = "cpuminer" ascii nocase
        $minerd = "minerd" ascii nocase
        $cgminer = "cgminer" ascii nocase
        $bfgminer = "bfgminer" ascii nocase
        $ethminer = "ethminer" ascii nocase
        $claymore = "claymore" ascii nocase
        $phoenixminer = "phoenixminer" ascii nocase
        $nbminer = "nbminer" ascii nocase
        $t_rex = "t-rex.exe" ascii nocase
    condition:
        any of them
}
