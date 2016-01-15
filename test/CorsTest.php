<?php

require_once "vendor/autoload.php";

class CorsTest extends PHPUnit_Framework_TestCase
{
    private $defaultHeaders = array(
        'Access-Control-Allow-Credentials' => 'true',
        'Access-Control-Allow-Headers' => 'Content-Type, X-Requested-With',
        'Access-Control-Allow-Methods' => 'OPTIONS',
        'Access-Control-Expose-Headers' => ''
    );

    public function testNoAllowedOrigins()
    {
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => 'https://foo.example.com'
        ), array());
        $this->assertFalse($cors->getEnabled());
        $this->assertEmpty($cors->getHeaders());
    }

    public function testNoRequestOrigin()
    {
        $cors = new \blinkmobile\Cors(array(), array(
            'allowOrigins' => array('https://*.example.com')
        ));
        $this->assertFalse($cors->getEnabled());
        $this->assertEmpty($cors->getHeaders());
    }

    public function testAllowedOriginMismatch()
    {
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => 'https://bah.example.com'
        ), array(
            'allowOrigins' => array('https://foo.example.com')
        ));
        $this->assertFalse($cors->getEnabled());
        $this->assertEmpty($cors->getHeaders());
    }

    public function testAllowedOriginsWildCard()
    {
        $requestOrigin = 'https://foo.example.com';
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => $requestOrigin
        ), array(
            'allowOrigins' => array('*')
        ));
        $this->assertTrue($cors->getEnabled());
        $expectedHeaders = array_merge($this->defaultHeaders, array(
            'Access-Control-Allow-Origin' => $requestOrigin
        ));
        $this->assertEquals($cors->getHeaders(), $expectedHeaders);
    }

    public function testAllowedOriginsMatch()
    {
        $requestOrigin = 'https://foo.example.com';
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => $requestOrigin
        ), array(
            'allowOrigins' => array($requestOrigin)
        ));
        $this->assertTrue($cors->getEnabled());
        $expectedHeaders = array_merge($this->defaultHeaders, array(
            'Access-Control-Allow-Origin' => $requestOrigin
        ));
        $this->assertEquals($cors->getHeaders(), $expectedHeaders);
    }

    public function testExtraHeadersAndMethods()
    {
        $requestOrigin = 'https://foo.example.com';
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => $requestOrigin
        ), array(
            'allowOrigins' => array($requestOrigin),
            'allowHeaders' => array('X-Blink-Config'),
            'allowMethods' => array('GET', 'POST')
        ));
        $this->assertTrue($cors->getEnabled());
        $expectedHeaders = array_merge($this->defaultHeaders, array(
            'Access-Control-Allow-Origin' => $requestOrigin,
            'Access-Control-Allow-Headers' => 'Content-Type, X-Requested-With, X-Blink-Config',
            'Access-Control-Allow-Methods' => 'OPTIONS, GET, POST'
        ));
        $this->assertEquals($cors->getHeaders(), $expectedHeaders);
    }

    public function testDisableCredentials()
    {
        $requestOrigin = 'https://foo.example.com';
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => $requestOrigin
        ), array(
            'allowOrigins' => array($requestOrigin),
            'allowCredentials' => false
        ));
        $this->assertTrue($cors->getEnabled());
        $expectedHeaders = array_merge($this->defaultHeaders, array(
            'Access-Control-Allow-Origin' => $requestOrigin,
            'Access-Control-Allow-Credentials' => 'false'
        ));
        $this->assertEquals($cors->getHeaders(), $expectedHeaders);
    }

    public function testAllowedSubOriginsMismatch()
    {
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => 'https://bah.example.com'
        ), array(
            'allowOrigins' => array('https://*.cloudfront.net')
        ));
        $this->assertFalse($cors->getEnabled());
        $this->assertEmpty($cors->getHeaders());
    }

    public function testAllowedSubSubOriginsMismatch()
    {
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => 'https://foo.bah.example.com'
        ), array(
            'allowOrigins' => array('https://*.example.com')
        ));
        $this->assertFalse($cors->getEnabled());
        $this->assertEmpty($cors->getHeaders());
    }

    public function testAllowedSubOriginsMatch()
    {
        $requestOrigin = 'https://foo.example.com';
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => $requestOrigin
        ), array(
            'allowOrigins' => array('https://*.example.com')
        ));
        $this->assertTrue($cors->getEnabled());
        $expectedHeaders = array_merge($this->defaultHeaders, array(
            'Access-Control-Allow-Origin' => $requestOrigin
        ));
        $this->assertEquals($cors->getHeaders(), $expectedHeaders);
    }

    public function testAllowedSubSubOriginsMatch()
    {
        $requestOrigin = 'https://foo.bah.example.com';
        $cors = new \blinkmobile\Cors(array(
            'HTTP_ORIGIN' => $requestOrigin
        ), array(
            'allowOrigins' => array('https://*.*.example.com')
        ));
        $this->assertTrue($cors->getEnabled());
        $expectedHeaders = array_merge($this->defaultHeaders, array(
            'Access-Control-Allow-Origin' => $requestOrigin
        ));
        $this->assertEquals($cors->getHeaders(), $expectedHeaders);
    }

}
