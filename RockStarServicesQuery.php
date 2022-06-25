<?php
header('Content-Type: application/json');
header('Acces-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: *');

$url  = 'https://support.rockstargames.com/services/status.json';
$tags = [
	'general'    => 'General',
	'rdo'        => 'Red Dead Online',
	'gtao'       => 'Grand Theft Auto Online',
	'sc'         => 'Social Club',
	'support'    => 'Support',
	'rglauncher' => 'Rockstar Games Launcher'
];

if(empty($_GET)) {
	throwJSON(500, '参数不合法!');
}

$serviceTag = strtolower($_GET['tag'] ?? '');
$getData    = strtolower($_GET['gd'] ?? 'all');

if(!isset($tags[$serviceTag])) {
	throwJSON(501, '不存在的服务!');
}


$contents = file_get_contents($url);
$json     = json_decode($contents, true);
$updated  = $json['updated']; // 数据更新时间;
$services = $json['services'];

if($getData === 'all') {
	$list     = [];
	foreach($services as $k => $data) {
		$list[$data['tag']] = $k;
	}
	$service = $services[$list[$serviceTag]];

	throwJSON(200, 'ok', true, [
		'名称'         => $service['name'],
		'服务器状态'    => parse($service['status_tag']),
		'上次更新时间'  => $service['recent_update'],
		'服务信息'      => $service['message'],
		'R星服务页状态' => $updated
	]);
}


/**
 * @method      throwJSON
 * @description 返回JSON
 * @author      HanskiJay
 * @doneIn      2022-06-25
 * @param       integer      $code    错误代码
 * @param       string       $message 描述信息
 * @param       boolean      $status  状态
 * @param       array        $array   自定义数组
 * @return      void
 */
function throwJSON($code, $message, $status = false, $array = [])
{
	exit(json_encode(array_merge([
		'status'    => $status,
		'errorCode' => $code,
		'message'   => $message
	], $array), JSON_UNESCAPED_UNICODE));
}

function parse($str)
{
	switch(strtolower($str)) {
		case 'up':
		return '在线';

		case 'down':
		return '已宕机';

		case 'limitted':
		return '访问受限';
	}
}