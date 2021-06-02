<?php

namespace Blindnet\BlindnetSDKPHP;

use DateTimeImmutable;

use Ramsey\Uuid\Uuid;
use Base64Url\Base64Url;
use Blindnet\BlindnetSDKPHP\Exception\AuthenticationException;
use Blindnet\BlindnetSDKPHP\Exception\BlindnetException;

class Blindnet {

    protected static $appKey;
    protected static $appId;
    protected static $clientToken;
    protected static $apiEndpoint;

    private function __construct($appKey, $appId, $apiEndpoint) {
        self::$appKey = base64_decode($appKey);
        self::$appId = $appId;
        self::$apiEndpoint = $apiEndpoint;
        $this->refreshClientToken();
    }

    /**
     * Creates an instance of Blindnet.
     * 
     * @param string $appKey Application private Ed25519 key (base64 encoded)
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
        $exp = $now->modify('+30 minutes')->getTimestamp();
        $tokenId = Uuid::uuid4();
        $header = json_encode(array('typ' => 'tjwt', 'alg' => 'EdDSA'));
        $payload = json_encode(array('app' => self::$appId, 'tid' => $tokenId, 'gid' => $groupId, 'exp' => $exp));
        return $this->createAndSign($header, $payload);
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
        $exp = $now->modify('+12 hours')->getTimestamp();
        $header = json_encode(array('typ' => 'jwt', 'alg' => 'EdDSA'));
        $payload = json_encode(array('uid' => $userId, 'app' => self::$appId, 'gid' => $groupId, 'exp' => $exp));
        return $this->createAndSign($header, $payload);
    }

    private function refreshClientToken() {
        $now = new DateTimeImmutable();
        $exp = $now->modify('+24 hours')->getTimestamp();
        $tokenId = Uuid::uuid4();
        $header = json_encode(array('typ' => 'cjwt', 'alg' => 'EdDSA'));
        $payload = json_encode(array('app' => self::$appId, 'tid' => $tokenId, 'exp' => $exp));
        self::$clientToken = $this->createAndSign($header, $payload);
    }

    private function createAndSign($header, $payload) {
        $temp = Base64Url::encode($header) . '.' . Base64Url::encode($payload);
        $sig = Base64Url::encode(sodium_crypto_sign_detached($temp, self::$appKey));
        return $temp . '.' . $sig;
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