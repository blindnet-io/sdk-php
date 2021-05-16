<?php

namespace Blindnet\BlindnetSDKPHP;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer;
use Ramsey\Uuid\Uuid;
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

    /**
     * Creates an instance of Blindnet.
     * 
     * @param string $appKey Application private Ed25519 key
     * @param string $appId Appicartion ID
     * @param string $apiEndpoint Optional API endpoint URL. Default value is 'https://api.blindnet.io'
     * 
     * @return Blindnet A Blindnet instance
     */
    static function init(string $appKey, string $appId, string $apiEndpoint = 'https://api.blindnet.io'): Blindnet {
        return new Blindnet($appKey, $appId, $apiEndpoint);
    }

    /**
     * Creates a JWT for non-registered users of your application, usually data senders.
     * 
     * @param string $groupId ID of the group to which a data sender is sending the data
     * 
     * @return string JWT for a non-registered user
     */
    function createTempUserToken(string $groupId): string {
        $now = new DateTimeImmutable();
        $tokenId = Uuid::uuid4();
        $builder = self::$jwtConfig->builder()
                ->withHeader('typ', 'tjwt')
                ->withClaim('app', self::$appId)
                ->withClaim('tid', $tokenId)
                ->withClaim('gid', $groupId)
                ->expiresAt($now->modify('+30 minutes'));
        return $this->createJwt($builder);
    }

    /**
     * Creates a JWT for registered users of your application, usually data receivers.
     * 
     * @param string $userId ID of a registered user
     * @param string $groupId ID of the group to which a registered user belongs
     * 
     * @return string JWT for a registered user
     */
    function createUserToken(string $userId, string $groupId): string {
        $now = new DateTimeImmutable();
        $builder = self::$jwtConfig->builder()
                ->withHeader('typ', 'jwt')
                ->withClaim('uid', $userId)
                ->withClaim('app', self::$appId)
                ->withClaim('gid', $groupId)
                ->expiresAt($now->modify('+12 hours'));
        return $this->createJwt($builder);
    }

    private function refreshClientToken() {
        $now = new DateTimeImmutable();
        $tokenId = Uuid::uuid4();
        $builder = self::$jwtConfig->builder()
                ->withHeader('typ', 'cjwt')
                ->withClaim('app', self::$appId)
                ->withClaim('tid', $tokenId)
                ->expiresAt($now->modify('+24 hours'));
        self::$clientToken = $this->createJwt($builder);
    }

    private function createJwt($builder) {
        $token = $builder->getToken(self::$jwtConfig->signer(), self::$jwtConfig->signingKey());
        return $token->toString();
    }

    /**
     * Deletes an encrypted data key from blindnet.
     * 
     * @param string $dataId ID of the data to delete
     * 
     * @return True If the deletion is successful 
     * 
     * @throws AuthenticationException When request to blindnet is unauthenticated
     * @throws BlindnetException When request to blindnet is not successful 
     */
    function forgetData(string $dataId): bool {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/documents/' . $dataId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while forgeting the data with id ' . $dataId);
    }

    /**
     * Deletes all encrypted data keys of a given user.
     * 
     * @param string $userId ID of a user to revoke access
     * 
     * @return True If the access revokation is successful 
     * 
     * @throws AuthenticationException When request to blindnet is unauthenticated
     * @throws BlindnetException When request to blindnet is not successful 
     */
    function revokeAccess(string $userId): bool {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/documents/user/' . $userId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while revoking access to user with id ' . $userId);
    }

    /**
     * Deletes a user from blindnet.
     * 
     * @param string $dataId ID of a user to delete
     * 
     * @return True If the deletion is successful 
     * 
     * @throws AuthenticationException When request to blindnet is unauthenticated
     * @throws BlindnetException When request to blindnet is not successful 
     */
    function forgetUser(string $userId): bool {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/users/' . $userId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while forgeting the user with id ' . $userId);
    }

    /**
     * Deletes a group from blindnet.
     * 
     * Deletes all users that belong to the group and all their encrypted data keys.
     * 
     * @param string $groupId ID of a group to delete
     * 
     * @return True If the deletion is successful 
     * 
     * @throws AuthenticationException When request to blindnet is unauthenticated
     * @throws BlindnetException When request to blindnet is not successful 
     */
    function forgetGroup(string $groupId): bool {
        $defaults = array(
            CURLOPT_URL => self::$apiEndpoint . '/api/v1/group/' . $groupId,
            CURLOPT_CUSTOMREQUEST => 'DELETE',
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'], 
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => array('Authorization: Bearer ' . self::$clientToken)
        );
        return $this->makeReq($defaults, true, 'Error while forgeting the group with id ' . $groupId);
    }

    private function makeReq($data, $isFirst, $excMsg): bool {
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