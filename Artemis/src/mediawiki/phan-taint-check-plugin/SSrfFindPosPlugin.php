<?php


use ast\Node;
use Phan\CodeBase;
use Phan\Language\Context;
use Phan\Language\Element\FunctionInterface;
use SecurityCheckPlugin\FunctionTaintedness;
use SecurityCheckPlugin\PreTaintednessVisitor;
use SecurityCheckPlugin\SSrfVisitor;
use SecurityCheckPlugin\SecurityCheckPlugin;
use SecurityCheckPlugin\Taintedness;
use SecurityCheckPlugin\TaintednessVisitor;

const USE_APP_SOURCE = true;

class SSrfFindPosPlugin extends SecurityCheckPlugin
{

    /**
     * @inheritDoc
     */
    public static function getPostAnalyzeNodeVisitorClassName(): string
    {
        return SSrfVisitor::class;
    }

    /**
     * @inheritDoc
     */
    public static function getPreAnalyzeNodeVisitorClassName(): string
    {
        return PreTaintednessVisitor::class;
    }

    /**
     * @inheritDoc
     */
    protected function getCustomFuncTaints(): array
    {
        $custom_taints = [
            '\file_get_contents' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\file' => [
                self::CUSTOM1_EXEC_TAINT | self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\curl_setopt_array' => [
                self::NO_TAINT,
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\curl_exec' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\curl_init' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\fsockopen' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\readfile' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\fopen' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\copy' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\simplexml_load_file' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\getimagesize' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\imagecreatefromgd' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\SimpleXMLElement::__construct' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\imagecreatefromgd2' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\imagecreatefromgd2part' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\imagecreatefromgif' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\imagecreatefromjpeg' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\imagecreatefrompng' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],

/*            '\scandir' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
/*            '\is_readable' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
            '\filemtime' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\filetype' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\filegroup' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\fileowner' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\filesize' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\is_link' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
/*            '\is_file' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\is_dir' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
            '\is_executable' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
/*            '\is_writable' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
/*            '\is_writeable' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
            '\file_put_contents' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
/*            '\file_exists' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
            '\fileatime' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\filectime' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\lstat' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\parse_ini_file' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\stat' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\touch' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
/*            '\mkdir' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\rmdir' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
            '\lchgrp' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\lchown' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\chgrp' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\chown' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
/*            '\rename' => [
                self::CUSTOM2_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
        ];
        if (!USE_APP_SOURCE) {
            return $custom_taints;
        }
        return $custom_taints + [
            '\wp_remote_get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\wp_remote_post' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
                '\curl_fetch_web_data::get_url_data' => [
                    self::CUSTOM1_EXEC_TAINT,
                    'overall' => self::NO_TAINT
                ],
            '\wp_remote_request' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
                '\explode' => [
                  self::NO_TAINT,
                    self::CUSTOM1_TAINT | self::CUSTOM2_TAINT,
                    'overall' => self::NO_TAINT
                ],
            '\HTTP_Request::__construct' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\think\Request::param' => [
                'overall' => self::YES_TAINT | self::CUSTOM2_TAINT
            ],
            '\think\Request::get' => [
                'overall' => self::YES_TAINT | self::CUSTOM2_TAINT
            ],
            '\think\Request::post' => [
                'overall' => self::YES_TAINT | self::CUSTOM2_TAINT
            ],
            '\WP_Http::request' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
/*            '\Uploader::__construct' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],*/
/*            '\NinjaTables\Framework\Request\Request::get' => [
                'overall' => self::YES_TAINT
            ],*/
                'sanitize_url' => [
                    self::CUSTOM1_TAINT | self::CUSTOM2_TAINT,
                    'overall' => self::NO_TAINT
                ],
            '\Symfony\Component\HttpFoundation\Request::get' => [
                'overall' => self::YES_TAINT | self::CUSTOM2_TAINT
            ],
            '\Symfony\Component\Filesystem\Filesystem::copy' => [
                self::CUSTOM1_EXEC_TAINT, 
                self::NO_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\GuzzleHttp\Client::get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\GuzzleHttp\Client::request' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\GuzzleHttp\Client::post' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
                '\GuzzleHttp\Psr7\Request::__construct' => [
                    self::NO_TAINT,
                    self::CUSTOM1_EXEC_TAINT,
                    'overall' => self::NO_TAINT
                ],
/*            '\SLiMS\Http\Client::get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],    */        
            '\Foo::test' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::YES_TAINT
            ],
            '\phpbb\request\request::variable' => [
                'overall' => self::YES_TAINT
            ],
            '\Psr\Http\Message\UploadedFileInterface::getStream' => [
                'overall' => self::YES_TAINT
            ],
/*            '\Intervention\Image\ImageManager::make' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ]*/
            '\Zend\Http\Client\Adapter\AdapterInterface::connect' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\System\input::get' => [
                'overall' => self::YES_TAINT
            ],
            '\form::input' => [
                'overall' => self::YES_TAINT
            ],
            '\Modules\Core\Downloader\Downloader::downloadFile' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Symfony\Component\HttpFoundation\Request::request' => [
                'overall' => self::YES_TAINT
            ],
            '\Symfony\Component\HttpFoundation\InputBag::all' => [
                'overall' => self::YES_TAINT
            ],
            '\Symfony\Component\HttpFoundation\Request::query' => [
                'overall' => self::YES_TAINT
            ],
            '\WebSocket\Client::__construct' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Illuminate\Http\Client\PendingRequest::send' => [
                self::NO_TAINT,
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Illuminate\Http\Client\PendingRequest::get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Illuminate\Http\Client\PendingRequest::post' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Illuminate\Http\Request::getContent' => [
                'overall' => self::YES_TAINT
            ],
            '\Illuminate\Foundation\Http\FormRequest::validated' => [
                'overall' => self::YES_TAINT
            ],
            '\Illuminate\Http\Request::json' => [
                'overall' => self::YES_TAINT
            ],
            '\Illuminate\Http\Request::input' => [
                'overall' => self::YES_TAINT
            ],
            '\Illuminate\Http\Request::all' => [
                'overall' => self::YES_TAINT
            ],
            '\Illuminate\Http\Request::query' => [
                'overall' => self::YES_TAINT
            ],
                '\Illuminate\Http\Concerns\InteractsWithInput::input' => [
                    'overall' => self::YES_TAINT
                ],
            '\Lime\App::request' => [
                'overall' => self::YES_TAINT
            ],
            '\Lime\Request::param' => [
                'overall' => self::YES_TAINT
            ],
            '\Lime\App::param' => [
                'overall' => self::YES_TAINT
            ],
            '\SimplePie::set_feed_url' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Symfony\Contracts\HttpClient\HttpClientInterface::request' => [
                self::NO_TAINT,
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Dotclear\Helper\Network\HttpClient::initClient' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Dotclear\Helper\Network\HttpClient::get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Dotclear\Helper\Network\HttpClient::quickGet' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Dotclear\Helper\Network\HttpClient::quickPost' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\input' => [
                'overall' => self::YES_TAINT
            ],
            '\Slim\Http\Request::getQueryParam' => [
                'overall' => self::YES_TAINT
            ],
            '\Alltube\Library\Downloader::getVideo' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\WP_REST_Request::get_params' => [
                'overall' => self::YES_TAINT
            ],
                '\WP_REST_Request::get_header' => [
                    'overall' => self::YES_TAINT
                ],
            '\db_mysqli::find' => [
                'overall' => self::YES_TAINT
            ],
            '\mysqli_result::fetch_object' => [
                'overall' => self::YES_TAINT
            ],
/*            '\wpdb::get_var' => [
                'overall' => self::YES_TAINT
            ],
            '\wpdb::get_row' => [
                'overall' => self::YES_TAINT
            ],
            '\wpdb::get_results' => [
                'overall' => self::YES_TAINT
            ],
            '\wpdb::get_col' => [
                'overall' => self::YES_TAINT
            ],
            '\wpdb::get_col_info' => [
                'overall' => self::YES_TAINT
            ],*/
            '\Input::str' => [
                'overall' => self::YES_TAINT
            ],
            '\HTTPClient::get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\go\core\http\Client::download' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\http_build_query' => [
                'overall' => self::NO_TAINT
            ],
            '\gophp\curl::__construct' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Curl\Curl::get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\HttpSocket::get' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
                '\http_class::GetRequestArguments' => [
                  self::CUSTOM1_EXEC_TAINT,
                    'overall' => self::NO_TAINT
                ],
            '\HttpSocket::post' => [
                self::CUSTOM1_EXEC_TAINT,
                'overall' => self::NO_TAINT
            ],
            '\Espo\Core\Api\Request::getParsedBody' => [
                'overall' => self::YES_TAINT
            ],
                '\Friendica\Network\IHTTPRequest::head' => [
                    self::CUSTOM1_EXEC_TAINT,
                    'overall' => self::NO_TAINT
                ],
'\Friendica\Network\IHTTPRequest::get' => [
                    self::CUSTOM1_EXEC_TAINT,
                    'overall' => self::NO_TAINT
                ],
'\Friendica\Network\IHTTPRequest::post' => [
                    self::CUSTOM1_EXEC_TAINT,
                    'overall' => self::NO_TAINT
                ],
                '\Cake\Http\ServerRequest::getData' => [
                    'overall' => self::YES_TAINT
                ],
            ];
    }

    public function isFalsePositive(int $combinedTaint, string &$msg, \Phan\Language\Context $context, \Phan\CodeBase $code_base): bool
    {
        if ($combinedTaint === self::CUSTOM1_TAINT) {
            if ($context->isInFunctionLikeScope()) {
                $func = $context->getFunctionLikeFQSEN();
                if (strpos($func, 'proxy_simplexml_load_file') !== false) {
                    return true;
                }
            }


        }
        return parent::isFalsePositive($combinedTaint, $msg, $context, $code_base);
    }

    public function modifyArgTaint(Taintedness $curArgTaintedness, Node $argument, int $argIndex, FunctionInterface $func, FunctionTaintedness $funcTaint, Context $context, CodeBase $code_base): Taintedness
    {
        if ($argument->kind === \ast\AST_ENCAPS_LIST) {
            $lhs = $argument->children[0];
            if (gettype($lhs) === 'string') {
                if ($lhs !== 'http://' && $lhs !== 'https://') {
                    return Taintedness::newSafe();
                }
            }
        }

        return parent::modifyArgTaint($curArgTaintedness, $argument, $argIndex, $func, $funcTaint, $context, $code_base);
    }

    public function modifyParamSinkTaint(Taintedness $paramSinkTaint, Taintedness $curArgTaintedness, Node $argument, int $argIndex, FunctionInterface $func, FunctionTaintedness $funcTaint, Context $context, CodeBase $code_base): Taintedness
    {
        if ($argument->kind === \ast\AST_PROP) {
           $ctx = new \Phan\AST\ContextNode($code_base, $context, $argument);
           try {
                $prop = $ctx->getProperty(false);
                if (isset($prop->marked) && $prop->marked) {
                   return Taintedness::newSafe();
               }
              } catch (\Exception $e) {
           }
        }
        if ($argument->kind === \ast\AST_VAR) {
            $ctx = new \Phan\AST\ContextNode($code_base, $context, $argument);
            try {
                $var = $ctx->getVariable();
                if (isset($var->marked) && $var->marked) {
                    return Taintedness::newSafe();
                }
            } catch (\Exception $e) {
            }
        }
        if ($argument->kind === \ast\AST_ENCAPS_LIST) {
            $lhs = $argument->children[0];
            if (gettype($lhs) === 'string') {
                if ($lhs !== 'http://' && $lhs !== 'https://') {
                    return Taintedness::newSafe();
                }
            }
        }
        return parent::modifyParamSinkTaint($paramSinkTaint, $curArgTaintedness, $argument, $argIndex, $func, $funcTaint, $context, $code_base); // TODO: Change the autogenerated stub
    }

}

return new SSrfFindPosPlugin;