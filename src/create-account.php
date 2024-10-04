<?php

require 'vendor/autoload.php';

use kornrunner\Keccak;
use Elliptic\EC;

$ec = new EC('secp256k1');

$key = $ec->genKeyPair();
$priv = $ec->keyFromPrivate($key->priv);
$pubKeyHex = $priv->getPublic(false, "hex");

$pubKeyBin = hex2bin($pubKeyHex);
$addressHex = getAddressHex($pubKeyBin);
$addressBin = hex2bin($addressHex);
$addressBase58 = getBase58CheckAddress($addressBin);

file_put_contents(
    filename: rand(1, 100) . 'account.txt',
    data: 'HEX: ' . $priv->getPrivate('hex') . PHP_EOL
    . 'Public key: ' . $pubKeyHex . PHP_EOL
    . 'Address hex: ' . $addressHex . PHP_EOL
    . 'Address base58: ' . $addressBase58 . PHP_EOL
);

function getAddressHex($pubKeyBin): string
{
    if (strlen($pubKeyBin) == 65) {
        $pubKeyBin = substr($pubKeyBin, 1);
    }

    $hash = Keccak::hash($pubKeyBin, 256);

    return '41' . substr($hash, 24);
}

function getBase58CheckAddress($addressBin): ?string
{
    $hash0 = hash('sha256', $addressBin, true);
    $hash1 = hash('sha256', $hash0, true);
    $checksum = substr($hash1, 0, 4);
    $checksum = $addressBin . $checksum;

    return base58encode(base2dec($checksum, 256));
}

function base58encode($num, $length = 58): ?string
{
    return dec2base($num, $length, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
}

function dec2base($dec, $base, $digits = false)
{
    if (extension_loaded('bcmath')) {
        if ($base < 2 || $base > 256) {
            die("Invalid Base: " . $base);
        }
        bcscale(0);
        $value = "";
        if (!$digits) {
            $digits = digits($base);
        }
        while ($dec > $base - 1) {
            $rest = bcmod($dec, $base);
            $dec = bcdiv($dec, $base);
            $value = $digits[$rest] . $value;
        }
        return $digits[intval($dec)] . $value;
    } else {
        die('Please install BCMATH');
    }
}

function base2dec($value, $base, $digits = false)
{
    if (extension_loaded('bcmath')) {
        if ($base < 2 || $base > 256) {
            die("Invalid Base: " . $base);
        }
        bcscale(0);
        if ($base < 37) {
            $value = strtolower($value);
        }
        if (!$digits) {
            $digits = digits($base);
        }
        $size = strlen($value);
        $dec = "0";
        for ($loop = 0; $loop < $size; $loop++) {
            $element = strpos($digits, $value[$loop]);
            $power = bcpow($base, $size - $loop - 1);
            $dec = bcadd($dec, bcmul($element, $power));
        }
        return (string)$dec;
    } else {
        die('Please install BCMATH');
    }
}

function digits($base): string
{
    if ($base > 64) {
        $digits = "";
        for ($loop = 0; $loop < 256; $loop++) {
            $digits .= chr($loop);
        }
    } else {
        $digits = "0123456789abcdefghijklmnopqrstuvwxyz";
        $digits .= "ABCDEFGHIJKLMNOPQRSTUVWXYZ-_";
    }

    return substr($digits, 0, $base);
}




