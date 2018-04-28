<?php
/**
 * Dida Framework  -- A Rapid Development Framework
 * Copyright (c) Zeupin LLC. (http://zeupin.com)
 *
 * Licensed under The MIT License.
 * Redistributions of files must retain the above copyright notice.
 */

namespace Dida\Wx;

class Wx
{
    const VERSION = '20180428';

    protected $appid;
    protected $sessionKey;


    public function decryptData($encryptedData, $iv)
    {
        if (strlen($this->sessionKey) != 24) {
            return WxError::$IllegalAESKey;
        }
        $aesKey = base64_decode($this->sessionKey);

        if (strlen($iv) != 24) {
            return WxError::$IllegalIV;
        }
        $aesIV = base64_decode($iv);

        $aesCipher = base64_decode($encryptedData);

        $result = openssl_decrypt($aesCipher, "AES-128-CBC", $aesKey, 1, $aesIV);

        $dataObj = json_decode($result);
        if ($dataObj == NULL) {
            return WxError::$IllegalBuffer;
        }

        if ($dataObj->watermark->appid != $this->appid) {
            return WxError::$IllegalWatermark;
        }
        $data = $result;

        return [0, null, $data];
    }
}
