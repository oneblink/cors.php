<?php

namespace blinkmobile;

class Cors
{
    private $allowCredentials = true;
    private $allowHeaders = array('Content-Type', 'X-Requested-With');
    private $allowMethods = array('OPTIONS');
    private $allowOrigins = array();
    private $exposeHeaders = array();

    private $isEnabled = false;

    private $requestOrigin = '';

    public function __construct(array $_server = array(), array $options = array())
    {
        if (array_key_exists('HTTP_ORIGIN', $_server) && !empty($_server['HTTP_ORIGIN'])) {
            $this->requestOrigin = $_server['HTTP_ORIGIN'];
        }
        foreach (array(
            'allowHeaders', 'allowMethods', 'allowOrigins', 'exposeHeaders',
        ) as $prop) {
            if (array_key_exists($prop, $options) && is_array($options[$prop])) {
                $this->$prop = array_merge($this->$prop, $options[$prop]);
            }
        }
        if (array_key_exists('allowCredentials', $options) && is_bool($options['allowCredentials'])) {
            $this->allowCredentials = $options['allowCredentials'];
        }

        $this->isEnabled = $this->isOriginMatch();
    }

    public function getHeaders()
    {
        if (!$this->isEnabled) {
            return array();
        }

        return array(
            'Access-Control-Allow-Origin' => $this->requestOrigin,
            'Access-Control-Allow-Credentials' => $this->allowCredentials ? 'true' : 'false',
            'Access-Control-Allow-Headers' => implode(', ', $this->allowHeaders),
            'Access-Control-Allow-Methods' => implode(', ', $this->allowMethods),
            'Access-Control-Expose-Headers' => implode(', ', $this->exposeHeaders),
        );
    }

    public function getEnabled()
    {
        return $this->isEnabled;
    }

    public function isOriginMatch()
    {
        if (empty($this->allowOrigins) || empty($this->requestOrigin)) {
            return false;
        }
        if (in_array('*', $this->allowOrigins)) {
            return true;
        }
        //$valid = '[^\s\.:]+'; // quite permissive
        $valid = '[\w\-]+'; // very strict
        foreach ($this->allowOrigins as $allowOrigin) {
            if (strpos($allowOrigin, '*') !== 0) { // wildcards
                $pattern = '|^'.preg_replace('|\*|', $valid, $allowOrigin).'$|';
                if (preg_match($pattern, $this->requestOrigin)) {
                    return true;
                }
            } elseif ($allowOrigin === $this->requestOrigin) {
                return true;
            }
        }

        return false;
    }

    /* example
    public static function sendHeaders($_server, $options)
    {
        $cors = new self($_server, $options);
        foreach ($cors->getHeaders() as $name => $value) {
            header($name.': '.$value);
        }
    }
    */

    public static function exitIfOptionsMethod()
    {
        if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
            exit();
        }
    }
}
