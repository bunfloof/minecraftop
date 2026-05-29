<?php
declare(strict_types=1);

const JAR_PATH       = __DIR__ . '/server.jar';
const ENTRY_NAME     = 'config.properties';
const PROTECTED_KEYS = ['key'];

$host = isset($_GET['host']) ? trim((string) $_GET['host']) : null;
$port = isset($_GET['port']) ? trim((string) $_GET['port']) : null;

function fail(int $code, string $msg) {
    http_response_code($code);
    header('Content-Type: text/plain');
    echo $msg;
    exit;
}

$hasBadChars = static fn(string $v): bool => preg_match('/[\x00-\x1F\x7F]/', $v) === 1;

if ($host !== null) {
    if ($hasBadChars($host)) {
        fail(400, 'Invalid host.');
    }
    $isIp   = filter_var($host, FILTER_VALIDATE_IP) !== false;
    $isHost = preg_match(
        '/^(?=.{1,253}$)([A-Za-z0-9](-?[A-Za-z0-9])*)(\.[A-Za-z0-9](-?[A-Za-z0-9])*)*$/',
        $host
    ) === 1;
    if (!$isIp && !$isHost) {
        fail(400, 'Invalid host.');
    }
}

if ($port !== null) {
    if (!ctype_digit($port) || (int) $port < 1 || (int) $port > 65535) {
        fail(400, 'Invalid port (must be 1-65535).');
    }
    $port = (string) (int) $port;
}

if ($host === null && $port === null) {
    fail(400, 'Nothing to change. Provide host and/or port.');
}

if (!is_file(JAR_PATH)) {
    fail(500, 'server.jar not found.');
}

$data = file_get_contents(JAR_PATH);
if ($data === false) {
    fail(500, 'Could not read server.jar.');
}

try {
    $entries = zipReadEntries($data);

    $found = false;
    foreach ($entries as &$e) {
        if ($e['name'] === ENTRY_NAME) {
            if ($e['method'] === 8) {
                $original = gzinflate($e['cdata']);
            } elseif ($e['method'] === 0) {
                $original = $e['cdata'];
            } else {
                fail(500, 'Unsupported compression method for ' . ENTRY_NAME . '.');
            }
            if ($original === false) {
                fail(500, 'Could not decompress ' . ENTRY_NAME . '.');
            }

            $new = updateProperties($original, $host, $port, PROTECTED_KEYS);

            $e['method'] = 8;
            $e['usize']  = strlen($new);
            $e['crc']    = crc32($new);
            $e['cdata']  = gzdeflate($new, 6);
            $e['csize']  = strlen($e['cdata']);
            $found = true;
        }
    }
    unset($e);

    if (!$found) {
        fail(500, ENTRY_NAME . ' not found in jar.');
    }

    $binary = zipBuild($entries);
} catch (\Throwable $ex) {
    fail(500, 'Failed to process jar: ' . $ex->getMessage());
}

header('Content-Type: application/java-archive');
header('Content-Disposition: attachment; filename="server.jar"');
header('Content-Length: ' . strlen($binary));
echo $binary;
exit;

function u16(string $s, int $o): int { return unpack('v', substr($s, $o, 2))[1]; }
function u32(string $s, int $o): int { return unpack('V', substr($s, $o, 4))[1]; }

function findEocd(string $data): int {
    $len = strlen($data);
    if ($len < 22) {
        return -1;
    }
    $start = max(0, $len - 22 - 65535);
    for ($i = $len - 22; $i >= $start; $i--) {
        if (substr($data, $i, 4) === "PK\x05\x06") {
            return $i;
        }
    }
    return -1;
}

function zipReadEntries(string $data): array {
    $eocd = findEocd($data);
    if ($eocd < 0) {
        throw new \RuntimeException('Not a valid zip/jar (no EOCD).');
    }

    $total    = u16($data, $eocd + 10);
    $cdOffset = u32($data, $eocd + 16);

    if ($cdOffset === 0xFFFFFFFF || $total === 0xFFFF) {
        throw new \RuntimeException('ZIP64 archives are not supported.');
    }

    $entries = [];
    $p = $cdOffset;

    for ($n = 0; $n < $total; $n++) {
        if (substr($data, $p, 4) !== "PK\x01\x02") {
            throw new \RuntimeException('Corrupt central directory.');
        }

        $versionMadeBy = u16($data, $p + 4);
        $flag          = u16($data, $p + 8);
        $method        = u16($data, $p + 10);
        $time          = u16($data, $p + 12);
        $date          = u16($data, $p + 14);
        $crc           = u32($data, $p + 16);
        $csize         = u32($data, $p + 20);
        $usize         = u32($data, $p + 24);
        $fnLen         = u16($data, $p + 28);
        $extraLen      = u16($data, $p + 30);
        $commentLen    = u16($data, $p + 32);
        $intAttr       = u16($data, $p + 36);
        $extAttr       = u32($data, $p + 38);
        $lho           = u32($data, $p + 42);
        $name          = substr($data, $p + 46, $fnLen);

        if ($flag & 0x1) {
            throw new \RuntimeException('Encrypted entries are not supported.');
        }
        if ($csize === 0xFFFFFFFF || $usize === 0xFFFFFFFF || $lho === 0xFFFFFFFF) {
            throw new \RuntimeException('ZIP64 entry is not supported.');
        }

        if (substr($data, $lho, 4) !== "PK\x03\x04") {
            throw new \RuntimeException('Corrupt local header.');
        }
        $lFnLen    = u16($data, $lho + 26);
        $lExtraLen = u16($data, $lho + 28);
        $dataStart = $lho + 30 + $lFnLen + $lExtraLen;
        $cdata     = substr($data, $dataStart, $csize);

        $entries[] = [
            'name'          => $name,
            'method'        => $method,
            'flag'          => $flag,
            'time'          => $time,
            'date'          => $date,
            'crc'           => $crc,
            'csize'         => $csize,
            'usize'         => $usize,
            'cdata'         => $cdata,
            'versionMadeBy' => $versionMadeBy,
            'intAttr'       => $intAttr,
            'extAttr'       => $extAttr,
        ];

        $p += 46 + $fnLen + $extraLen + $commentLen;
    }

    return $entries;
}

function zipBuild(array $entries): string {
    $out = '';
    $cd  = '';

    foreach ($entries as $e) {
        $offset = strlen($out);
        $flag = $e['flag'] & 0x800;
        $nLen = strlen($e['name']);

        $out .= "PK\x03\x04";
        $out .= pack('v', 20);
        $out .= pack('v', $flag);
        $out .= pack('v', $e['method']);
        $out .= pack('v', $e['time']);
        $out .= pack('v', $e['date']);
        $out .= pack('V', $e['crc']);
        $out .= pack('V', $e['csize']);
        $out .= pack('V', $e['usize']);
        $out .= pack('v', $nLen);
        $out .= pack('v', 0);
        $out .= $e['name'];
        $out .= $e['cdata'];

        $cd .= "PK\x01\x02";
        $cd .= pack('v', $e['versionMadeBy']);
        $cd .= pack('v', 20);
        $cd .= pack('v', $flag);
        $cd .= pack('v', $e['method']);
        $cd .= pack('v', $e['time']);
        $cd .= pack('v', $e['date']);
        $cd .= pack('V', $e['crc']);
        $cd .= pack('V', $e['csize']);
        $cd .= pack('V', $e['usize']);
        $cd .= pack('v', $nLen);
        $cd .= pack('v', 0);
        $cd .= pack('v', 0);
        $cd .= pack('v', 0);
        $cd .= pack('v', $e['intAttr']);
        $cd .= pack('V', $e['extAttr']);
        $cd .= pack('V', $offset);
        $cd .= $e['name'];
    }

    $cdOffset = strlen($out);
    $out .= $cd;
    $cdSize = strlen($cd);
    $count  = count($entries);

    $out .= "PK\x05\x06";
    $out .= pack('v', 0);
    $out .= pack('v', 0);
    $out .= pack('v', $count);
    $out .= pack('v', $count);
    $out .= pack('V', $cdSize);
    $out .= pack('V', $cdOffset);
    $out .= pack('v', 0);

    return $out;
}

function updateProperties(string $content, ?string $host, ?string $port, array $protected): string {
    $lines = preg_split('/\R/', $content);
    $seen  = ['host' => false, 'port' => false];

    foreach ($lines as $i => $line) {
        if ($line === '' || $line[0] === '#' || $line[0] === '!') {
            continue;
        }
        $eq = strpos($line, '=');
        if ($eq === false) {
            continue;
        }
        $name = trim(substr($line, 0, $eq));

        if (in_array($name, $protected, true)) {
            continue;
        }
        if ($name === 'host' && $host !== null) {
            $lines[$i]    = 'host=' . $host;
            $seen['host'] = true;
        }
        if ($name === 'port' && $port !== null) {
            $lines[$i]    = 'port=' . $port;
            $seen['port'] = true;
        }
    }

    if ($host !== null && !$seen['host']) {
        $lines[] = 'host=' . $host;
    }
    if ($port !== null && !$seen['port']) {
        $lines[] = 'port=' . $port;
    }

    return implode("\n", $lines);
}