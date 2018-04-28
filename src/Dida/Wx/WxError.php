<?php
/**
 * Dida Framework  -- A Rapid Development Framework
 * Copyright (c) Zeupin LLC. (http://zeupin.com)
 *
 * Licensed under The MIT License.
 * Redistributions of files must retain the above copyright notice.
 */

namespace Dida\Wx;

class WxError
{
    public static $IllegalAESKey = [-41001, "非法的AES密钥", null];
    public static $IllegalIV = [-41002, "非法的IV向量", null];
    public static $IllegalBuffer = [-41003, "非法的密文序列", null];
    public static $IllegalWatermark = [-41005, "数据水印校验异常", null];

    public static $DecodeBase64Error = [-10099, "Base64解码失败", null];

}
