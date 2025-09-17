<?php
/**
 * Nostr Event Publisher
 * Handles publishing events to Nostr relays using WebSocket connections
 */

class NostrCalendarPublisher {
    
    private $relays;
    
    public function __construct() {
        $this->relays = get_option('nostr_calendar_relays', [
            'wss://relay.damus.io',
            'wss://nos.lol'
        ]);
    }
    
    /**
     * Publish already signed event to Nostr relays
     */
    public function publish_event($signed_event) {
        error_log('[Nostr Calendar] Publishing signed event: ' . print_r($signed_event, true));
        
        try {
            // Validate the signed event structure
            if (!$this->validate_event($signed_event)) {
                return [
                    'success' => false,
                    'errors' => ['Invalid event structure']
                ];
            }
            
            // Publish to relays
            $results = $this->publish_to_relays($signed_event);
            
            return [
                'success' => count($results['successful']) > 0,
                'event' => $signed_event,
                'relays_published' => $results['successful'],
                'errors' => $results['failed']
            ];
            
        } catch (Exception $e) {
            return [
                'success' => false,
                'errors' => [$e->getMessage()]
            ];
        }
    }

    /**
     * Publish event to multiple Nostr relays
     */
    private function publish_to_relays($event) {
        $successful = [];
        $failed = [];
        
        foreach ($this->relays as $relay_url) {
            try {
                $result = $this->publish_to_relay($event, $relay_url);
                if ($result) {
                    $successful[] = $relay_url;
                } else {
                    $failed[] = $relay_url . ': Connection failed';
                }
            } catch (Exception $e) {
                $failed[] = $relay_url . ': ' . $e->getMessage();
            }
        }
        
        return [
            'successful' => $successful,
            'failed' => $failed
        ];
    }
    
    /**
     * Publish to single relay (updated to use improved websocket send and return reason)
     */
    private function publish_to_relay($event, $relay_url) {
        $message = json_encode(['EVENT', $event], JSON_UNESCAPED_SLASHES);
        $res = $this->send_websocket_message($relay_url, $message);

        if (is_array($res) && isset($res['success'])) {
            if ($res['success']) {
                error_log("Nostr Calendar: publish OK on {$relay_url} - reply: " . ($res['reply'] ?? ''));
                return true;
            } else {
                error_log("Nostr Calendar: publish FAILED on {$relay_url} - reason: " . ($res['reply'] ?? 'unknown'));
                return false;
            }
        }

        error_log("Nostr Calendar: publish UNKNOWN result on {$relay_url}");
        return false;
    }

    /**
     * Send WebSocket message (pure PHP implementation; evaluates relay replies)
     *
     * Returns array: ['success' => bool, 'reply' => string]
     */
    private function send_websocket_message($relay_url, $message) {
        $u = parse_url($relay_url);
        if ($u === false || !isset($u['host'])) {
            error_log("Nostr Calendar: invalid relay url {$relay_url}");
            return ['success' => false, 'reply' => 'invalid-url'];
        }

        $isSecure = (isset($u['scheme']) && strtolower($u['scheme']) === 'wss');
        $host = $u['host'];
        $port = isset($u['port']) ? (int)$u['port'] : ($isSecure ? 443 : 80);
        $path = (isset($u['path']) ? $u['path'] : '/') . (isset($u['query']) ? '?' . $u['query'] : '');

        $remote = ($isSecure ? 'ssl://' : '') . $host . ':' . $port;
        $errno = 0; $errstr = '';
        $ctx = stream_context_create();

        // Open socket
        $fp = @stream_socket_client($remote, $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp) {
            error_log("Nostr Calendar: socket connect failed to {$relay_url} - {$errno} {$errstr}");
            return ['success' => false, 'reply' => 'connect-failed: ' . trim("$errno $errstr")];
        }
        stream_set_timeout($fp, 8);
        stream_set_blocking($fp, true);

        // WebSocket handshake
        $key = base64_encode(random_bytes(16));
        $hostHeader = $host . ($port && (($isSecure && $port !== 443) || (!$isSecure && $port !== 80)) ? ":{$port}" : '');
        $headers = "GET {$path} HTTP/1.1\r\n" .
                   "Host: {$hostHeader}\r\n" .
                   "Upgrade: websocket\r\n" .
                   "Connection: Upgrade\r\n" .
                   "Sec-WebSocket-Key: {$key}\r\n" .
                   "Sec-WebSocket-Version: 13\r\n" .
                   "\r\n";
        fwrite($fp, $headers);

        // Read handshake response
        $handshake = '';
        $start = time();
        while (!feof($fp)) {
            $line = fgets($fp);
            if ($line === false) break;
            $handshake .= $line;
            if (rtrim($line) === '') break; // end headers
            if (time() - $start > 5) break;
        }

        if (stripos($handshake, '101') === false || stripos($handshake, 'upgrade: websocket') === false) {
            fclose($fp);
            error_log("Nostr Calendar: websocket handshake failed for {$relay_url} - response: " . trim($handshake));
            return ['success' => false, 'reply' => 'handshake-failed: ' . trim($handshake)];
        }

        // helper: send masked text frame (client->server must mask)
        $sendFrame = function($socket, $payload) {
            $payload = (string)$payload;
            $len = strlen($payload);
            $b1 = 0x81; // FIN + text
            if ($len <= 125) {
                $head = chr($b1) . chr(0x80 | $len); // mask bit set
            } elseif ($len <= 65535) {
                $head = chr($b1) . chr(0x80 | 126) . pack('n', $len);
            } else {
                $head = chr($b1) . chr(0x80 | 127) . pack('J', $len);
            }
            $mask = random_bytes(4);
            $masked = $payload ^ str_repeat($mask, (int)ceil($len / 4));
            // apply mask properly
            $out = $head . $mask;
            for ($i = 0; $i < $len; $i++) {
                $out .= $payload[$i] ^ $mask[$i % 4];
            }
            fwrite($socket, $out);
        };

        // helper: read a single frame (text) from server
        $readFrame = function($socket) {
            $b1 = ord(fread($socket, 1) ?: "\0");
            $b2 = ord(fread($socket, 1) ?: "\0");
            $fin = ($b1 & 0x80) !== 0;
            $opcode = $b1 & 0x0f;
            $masked = ($b2 & 0x80) !== 0;
            $len = $b2 & 0x7f;

            if ($len === 126) {
                $ext = fread($socket, 2);
                $arr = unpack('n', $ext);
                $len = $arr[1];
            } elseif ($len === 127) {
                $ext = fread($socket, 8);
                $arr = unpack('J', $ext);
                $len = $arr[1];
            }

            $maskKey = $masked ? fread($socket, 4) : null;
            $data = '';
            $remaining = $len;
            while ($remaining > 0) {
                $chunk = fread($socket, $remaining);
                if ($chunk === false || $chunk === '') break;
                $data .= $chunk;
                $remaining -= strlen($chunk);
            }

            if ($masked && $maskKey !== null) {
                $unmasked = '';
                for ($i = 0; $i < strlen($data); $i++) {
                    $unmasked .= $data[$i] ^ $maskKey[$i % 4];
                }
                $data = $unmasked;
            }

            return ['opcode' => $opcode, 'data' => $data, 'fin' => $fin];
        };

        // send message
        try {
            $sendFrame($fp, $message);
        } catch (\Throwable $e) {
            fclose($fp);
            error_log("Nostr Calendar: send frame failed to {$relay_url} - " . $e->getMessage());
            return ['success' => false, 'reply' => 'send-failed: ' . $e->getMessage()];
        }

        // wait for replies until OK/NOTICE/EOSE or timeout
        $replyText = '';
        $deadline = time() + 8;
        while (time() < $deadline && !feof($fp)) {
            // stream_select for readability with timeout
            $r = [$fp]; $w = $e = null;
            $tv = ($deadline - time());
            if ($tv < 0) $tv = 0;
            $num = stream_select($r, $w, $e, $tv, 0);
            if ($num === false) break;
            if ($num === 0) continue;
            $frame = $readFrame($fp);
            if (!$frame || !isset($frame['data'])) continue;
            $payload = trim($frame['data']);
            $replyText .= $payload . "\n";

            // try parse JSON arrays
            $parsed = json_decode($payload, true);
            if (is_array($parsed) && count($parsed) >= 1) {
                $type = strtoupper($parsed[0]);
                if ($type === 'OK') {
                    // ["OK", "<id>", true|false, "message"]
                    $okId = $parsed[1] ?? '';
                    $okFlag = $parsed[2] ?? false;
                    $okMsg = $parsed[3] ?? '';
                    fclose($fp);
                    if ($okFlag === true) {
                        return ['success' => true, 'reply' => json_encode($parsed)];
                    }
                    return ['success' => false, 'reply' => 'ok-false: ' . $okMsg];
                } elseif ($type === 'NOTICE') {
                    $reason = $parsed[1] ?? '';
                    fclose($fp);
                    return ['success' => false, 'reply' => 'notice: ' . $reason];
                } elseif ($type === 'EOSE') {
                    fclose($fp);
                    return ['success' => false, 'reply' => 'eose'];
                } else {
                    // other message - continue reading
                }
            }
        }

        // timeout / no decisive reply
        @fclose($fp);
        return ['success' => false, 'reply' => 'no-decisive-reply: ' . trim($replyText)];
    }
    
    /**
     * Validate Nostr event structure
     */
    public function validate_event($event) {
        $required_fields = ['id', 'pubkey', 'created_at', 'kind', 'tags', 'content', 'sig'];
        
        foreach ($required_fields as $field) {
            if (!isset($event[$field])) {
                error_log("Nostr Calendar: Missing field: {$field}");
                return false;
            }
        }
        
        // Validate pubkey format (64 char hex)
        if (!preg_match('/^[0-9a-f]{64}$/i', $event['pubkey'])) {
            error_log("Nostr Calendar: Invalid pubkey format: " . $event['pubkey']);
            return false;
        }
        
        // Validate signature format (128 char hex)
        if (!preg_match('/^[0-9a-f]{128}$/i', $event['sig'])) {
            error_log("Nostr Calendar: Invalid signature format: " . $event['sig']);
            return false;
        }
        
        // Validate event ID format (64 char hex)
        if (!preg_match('/^[0-9a-f]{64}$/i', $event['id'])) {
            error_log("Nostr Calendar: Invalid event ID format: " . $event['id']);
            return false;
        }
        
        return true;
    }
}