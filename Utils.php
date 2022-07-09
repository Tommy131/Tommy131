<?php

declare(strict_types=1);


class Utils
{

	/**
	 * 将字符串通过Rot13密码点对点加密
	 * @author      HanskiJay
	 * @doneIn      2022-07-09
	 * @param       string    $str
	 * @return      string
	 */
	public static function encryptString(string $str) : string
	{
		$str = base64_encode(strrev(str_rot13(base64_encode($str))));
		return $str;
	}


	/**
	 * 将数组以字符串形式输出
	 * @author      HanskiJay
	 * @since       2022-07-09
	 * @param       string  $arrayName
	 * @param       array   $array
	 * @param       boolean $useKey
	 */
	public static function Array2String(string $arrayName, array $array, bool $useKey = false) : void
	{
		$length = count($array);
		$count  = 0;
		$str    = "\${$arrayName} = [\n";

		foreach($array as $k => $v) {
			$count++;
			if($useKey) {
				$str .= "'{$key}' => '{$v}'";
			} else {
				$str .= "'{$v}'";
			}
			if($count < $length) {
				$str .= ',';
			}
			$str .= "\n";

		}
		$str .= '];';
		echo $str;
	}
}