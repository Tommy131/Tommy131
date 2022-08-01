<?php

namespace App\Http\Controllers\Server;

use App\Services\ServerService;
use App\Services\UserService;
use App\Utils\CacheKey;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Models\User;
use App\Models\Plan;
use App\Models\ServerV2ray;
use App\Models\ServerLog;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Cache;

/*
 * V2ray Poseidon
 * Github: https://github.com/ColetteContreras/trojan-poseidon
 */
class PoseidonController extends Controller
{
    CONST V2RAY_CONFIG = '{"api":{"services":["HandlerService","StatsService"],"tag":"api"},"dns":{},"stats":{},"inbound":{"listen":"0.0.0.0","port":443,"protocol":"vmess","settings":{"clients":[]},"sniffing":{"enabled":true,"destOverride":["http","tls"]},"streamSettings":{"network":"ws"},"tag":"proxy"},"inboundDetour":[{"listen":"127.0.0.1","port":23333,"protocol":"dokodemo-door","settings":{"address":"0.0.0.0"},"tag":"api"}],"log":{"loglevel":"debug","access":"access.log","error":"error.log"},"outbound":{"protocol":"freedom","settings":{}},"outboundDetour":[{"protocol":"blackhole","settings":{},"tag":"block"}],"routing":{"rules":[{"inboundTag":"api","outboundTag":"api","type":"field"}]},"policy":{"levels":{"0":{"handshake":4,"connIdle":300,"uplinkOnly":5,"downlinkOnly":30,"statsUserUplink":true,"statsUserDownlink":true}}}}';


    public $poseidonVersion;

    public function __construct(?Request $request = null)
    {
        if(is_null($request)) {
            $this->poseidonVersion = '1.0.0';
            return;
        }
        $this->poseidonVersion = $request->input('poseidon_version');
    }

    // 后端获取用户
    public function user(Request $request)
    {
        if ($r = $this->verifyToken($request)) { return $r; }

        $nodeId = $request->input('node_id');
        $server = ServerV2ray::find($nodeId);
        if (!$server) {
            return $this->error("server could not be found", 404);
        }
        Cache::put(CacheKey::get('SERVER_V2RAY_LAST_CHECK_AT', $server->id), time(), 3600);
        $serverService = new ServerService();
        $users = $serverService->getAvailableUsers($server->group_id);
        $result = [];
        foreach ($users as $user) {
            $user->v2ray_user = [
                "uuid" => $user->uuid,
                "email" => sprintf("%s@v2board.user", $user->uuid),
                "alter_id" => $server->alter_id ?? 1,
                "level" => 0,
            ];
            unset($user['uuid']);
            unset($user['email']);
            array_push($result, $user);
        }

        return $this->success($result);
    }

    // 后端提交数据
    public function submit(Request $request)
    {
        if ($r = $this->verifyToken($request)) { return $r; }
        $server = ServerV2ray::find($request->input('node_id'));
        if (!$server) {
            return $this->error("server could not be found", 404);
        }
        $data = file_get_contents('php://input');
        $data = json_decode($data, true);
        Cache::put(CacheKey::get('SERVER_V2RAY_ONLINE_USER', $server->id), count($data), 3600);
        Cache::put(CacheKey::get('SERVER_V2RAY_LAST_PUSH_AT', $server->id), time(), 3600);
        $userService = new UserService();
        foreach ($data as $item) {
            $u = $item['u'] * $server->rate;
            $d = $item['d'] * $server->rate;
            if (!$userService->trafficFetch($u, $d, $item['user_id'], $server, 'vmess')) {
                return $this->error("user fetch fail", 500);
            }
        }

        return $this->success('');
    }

    // 后端获取配置
    public function config(Request $request)
    {
        if ($r = $this->verifyToken($request)) { return $r; }

        $nodeId = $request->input('node_id');
        $localPort = $request->input('local_port');
        if (empty($nodeId) || empty($localPort)) {
            return $this->error('invalid parameters', 400);
        }

        try {
            $json = $this->getV2RayConfig($nodeId, $localPort);
            $json->poseidon = [
              'license_key' => (string)config('v2board.server_license'),
            ];
            if ($this->poseidonVersion >= 'v1.5.0') {
                // don't need it after v1.5.0
                unset($json->inboundDetour);
                unset($json->stats);
                unset($json->api);
                array_shift($json->routing->rules);
            }

            foreach($json->policy->levels as &$level) {
                $level->handshake = 2;
                $level->uplinkOnly = 2;
                $level->downlinkOnly = 2;
                $level->connIdle = 60;
            }

            return $this->success($json);
        } catch (\Exception $e) {
            return $this->error($e->getMessage(), 500);
        }
    }

    public function getV2RayConfig(int $nodeId, int $localPort)
    {
        $server = ServerV2ray::find($nodeId);
        if (!$server) {
            abort(500, '节点不存在');
        }
        $json = json_decode(self::V2RAY_CONFIG);
        $json->log->loglevel = 'debug';
        $json->inboundDetour[0]->port = (int)$localPort;
        $json->inbound->port = (int)$server->server_port;
        $json->inbound->streamSettings->network = $server->network;
        $this->setDns($server, $json);
        $this->setNetwork($server, $json);
        $this->setRule($server, $json);
        $this->setTls($server, $json);

        return $json;
    }

    protected function verifyToken(Request $request)
    {
        $token = $request->input('token');
        if (empty($token)) {
            return $this->error("token must be set");
        }
        if ($token !== config('v2board.server_token')) {
            return $this->error("invalid token");
        }
    }

    protected function error($msg, int $status = 400) {
        return response([
            'msg' => $msg,
        ], $status);
    }

    protected function success($data) {
         $req = request();
        // Only for "GET" method
        if (!$req->isMethod('GET') || !$data) {
            return response([
                'msg' => 'ok',
                'data' => $data,
            ]);
        }

        $etag = sha1(json_encode($data));
        if ($etag == $req->header("IF-NONE-MATCH")) {
            return response(null, 304);
        }

        return response([
            'msg' => 'ok',
            'data' => $data,
        ])->header('ETAG', $etag);
    }

    private function setDns(ServerV2ray $server, object $json)
    {
        if ($server->dnsSettings) {
            $dns = $server->dnsSettings;
            if (isset($dns->servers)) {
                array_push($dns->servers, '1.1.1.1');
                array_push($dns->servers, 'localhost');
            }
            $json->dns = $dns;
            $json->outbound->settings->domainStrategy = 'UseIP';
        }
    }

    private function setNetwork(ServerV2ray $server, object $json)
    {
        if ($server->networkSettings) {
            switch ($server->network) {
                case 'tcp':
                    $json->inbound->streamSettings->tcpSettings = $server->networkSettings;
                    break;
                case 'kcp':
                    $json->inbound->streamSettings->kcpSettings = $server->networkSettings;
                    break;
                case 'ws':
                    $json->inbound->streamSettings->wsSettings = $server->networkSettings;
                    break;
                case 'http':
                    $json->inbound->streamSettings->httpSettings = $server->networkSettings;
                    break;
                case 'domainsocket':
                    $json->inbound->streamSettings->dsSettings = $server->networkSettings;
                    break;
                case 'quic':
                    $json->inbound->streamSettings->quicSettings = $server->networkSettings;
                    break;
                case 'grpc':
                    $json->inbound->streamSettings->grpcSettings = $server->networkSettings;
                    break;
            }
        }
    }

    private function setRule(ServerV2ray $server, object $json)
    {
        $domainRules = array_filter(explode(PHP_EOL, config('v2board.server_v2ray_domain')));
        $protocolRules = array_filter(explode(PHP_EOL, config('v2board.server_v2ray_protocol')));
        if ($server->ruleSettings) {
            $ruleSettings = $server->ruleSettings;
            // domain
            if (isset($ruleSettings->domain)) {
                $ruleSettings->domain = array_filter($ruleSettings->domain);
                if (!empty($ruleSettings->domain)) {
                    $domainRules = array_merge($domainRules, $ruleSettings->domain);
                }
            }
            // protocol
            if (isset($ruleSettings->protocol)) {
                $ruleSettings->protocol = array_filter($ruleSettings->protocol);
                if (!empty($ruleSettings->protocol)) {
                    $protocolRules = array_merge($protocolRules, $ruleSettings->protocol);
                }
            }
        }
        if (!empty($domainRules)) {
            $domainObj = new \StdClass();
            $domainObj->type = 'field';
            $domainObj->domain = $domainRules;
            $domainObj->outboundTag = 'block';
            array_push($json->routing->rules, $domainObj);
        }
        if (!empty($protocolRules)) {
            $protocolObj = new \StdClass();
            $protocolObj->type = 'field';
            $protocolObj->protocol = $protocolRules;
            $protocolObj->outboundTag = 'block';
            array_push($json->routing->rules, $protocolObj);
        }
        if (empty($domainRules) && empty($protocolRules)) {
            $json->inbound->sniffing->enabled = false;
        }
    }

    private function setTls(ServerV2ray $server, object $json)
    {
        if ((int)$server->tls) {
            $tlsSettings = $server->tlsSettings;
            $json->inbound->streamSettings->security = 'tls';
            $tls = (object)[
                'certificateFile' => '/root/.cert/server.crt',
                'keyFile' => '/root/.cert/server.key'
            ];
            $json->inbound->streamSettings->tlsSettings = new \StdClass();
            if (isset($tlsSettings->serverName)) {
                $json->inbound->streamSettings->tlsSettings->serverName = (string)$tlsSettings->serverName;
            }
            if (isset($tlsSettings->allowInsecure)) {
                $json->inbound->streamSettings->tlsSettings->allowInsecure = (int)$tlsSettings->allowInsecure ? true : false;
            }
            $json->inbound->streamSettings->tlsSettings->certificates[0] = $tls;
        }
    }
}
