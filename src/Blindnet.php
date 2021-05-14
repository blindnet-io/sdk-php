<?php

namespace Blindnet\BlindnetSDKPHP;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer;
use Blindnet\BlindnetSDKPHP\Exception\AuthenticationException;
use Blindnet\BlindnetSDKPHP\Exception\BlindnetException;

class Blindnet {

    protected static $appKey;
    protected static $appId;
    protected static $clientToken;
    protected static $jwtConfig;
    protected static $apiEndpoint;

    private function __construct($appKey, $appId, $apiEndpoint) {
        self::$appKey = $appKey;
        self::$appId = $appId;
        self::$apiEndpoint = $apiEndpoint;
        self::$jwtConfig = Configuration::forAsymmetricSigner(
            new Signer\EdDSA(),
            InMemory::base64Encoded($appKey),
            InMemory::base64Encoded('')
        );
        $this->refreshClientToken();
    }

    static function init($appKey, $appId, $apiEndpoint = 'https://api.blindnet.io') {
        return new Blindnet($appKey, $appId, $apiEndpoint);
    }

    function createTempUserToken($groupId) {
        $now = new DateTimeImmutable();
        $tokenId = bin2hex(random_bytes(16));
        $builder = self::$jwtConfig->builder()
                ->withHeader('typ', 'tjwt')
                ->withClaim('app', self::$appId)
                ->withClaim('tid', $tokenId)
                ->withClaim('gid', $groupId)
                ->expiresAt($now->modify('+30 minutes'));
        return $this->createJwt($builder);
    }

    function createUserToken($userId, $groupId) {
        $now = new DateTimeImmutable();
        $builder = self::$jwtConfig->builder()
                ->withHeader('typ', 'jwt')
                ->withClaim('uid', $userId)
                ->withClaim('app', self::$appId)
                ->withClaim('gid', $groupId)
                ->expiresAt($now->modify('+30 minutes'));
        return $this->createJwt($builder);
    }

    private function refreshClientToken() {
        $now = new DateTimeImmutable();
        $tokenId = bin2hex(random_bytes(16));
        $builder = self::$jwtConfig->builder()
                ->withHeader('typ', 'cjwt')
                ->withClaim('app', self::$appId)
                ->withClaim('tid', $tokenId)
                ->expiresAt($now->modify('+30 minutes'));
        self::$clientToken = $this->createJwt($builder);
    }

    private function createJwt($builder) {
        $token = $builder->getToken(self::$jwtConfig->signer(), self::$jwtConfig->signingKey());
        return $token->toString();
    }

    function forgetData($dataId) {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/documents/' . $dataId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while forgeting the data with id ' . $dataId);
    }

    function revokeAccess($userId) {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/documents/user/' . $userId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while revoking access to user with id ' . $userId);
    }

    function forgetUser($userId) {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/users/' . $userId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while forgeting the user with id ' . $userId);
    }

    function forgetGroup($groupId) {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/group/' . $groupId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while forgeting the group with id ' . $groupId);
    }

    private function makeReq($data, $isFirst, $excMsg) {
        $ch = curl_init(); 
        curl_setopt_array($ch, $data);
        curl_exec($ch); 
        $httpcode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        if($httpcode == 401 && $isFirst) {
            $this->refreshClientToken();
            $this->makreReq($data, false);
        }
        elseif ($httpcode == 401) 
            throw new AuthenticationException();
        elseif ($httpcode == 200)
            return true;
        else 
            throw new BlindnetException($excMsg . '. API response code was ' . $httpcode);
    }
}
?>