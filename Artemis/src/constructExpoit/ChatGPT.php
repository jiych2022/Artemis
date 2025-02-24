<?php
namespace Construct;

class StreamType{
    const Event = 0; // for JavaScript EventSource
    const Plain = 1; // for terminal application
    const Raw   = 2; // for raw data from ChatGPT API
}

class ChatGPT {
    protected array $messages = [];
    protected array $functions = [];
    protected $savefunction = null;
    protected $loadfunction = null;
    protected bool $loaded = false;
    protected $tool_choice = "auto";
    protected $base_url = "https://api.gptsapi.net/v1";
    protected string $model = "gpt-4o-2024-08-06";
    protected array $params = [];
    protected bool $assistant_mode = false;
    protected ?Assistant $assistant = null;
    protected ?string $thread_id = null;
    protected ?Run $run = null;
    protected string $api_key;
    protected ?string $chat_id = null;

    public function __construct(
        string $api_key,
        ?string $chat_id = null
    ) {
        $this->chat_id = $chat_id;
        $this->api_key = $api_key;
        if( $this->chat_id === null ) {
            $this->chat_id = uniqid( "", true );
        }
    }

    public function load() {
        if( is_callable( $this->loadfunction ) ) {
            $this->messages = ($this->loadfunction)( $this->chat_id );
            $this->loaded = true;
        }
    }

    public function assistant_mode( bool $enabled ) {
        $this->assistant_mode = $enabled;
    }

    public function set_assistant(  $assistant ) {
        if( is_string( $assistant ) ) {
            $this->assistant = $this->fetch_assistant( $assistant );
        } else {
            $this->assistant = $assistant;
        }
    }

    public function set_thread( $thread ) {
        if( is_string( $thread ) ) {
            $this->thread_id = $thread;
        } else {
            $this->thread_id = $thread->get_id();
        }
    }

    public function set_model( string $model ) {
        $this->model = $model;
    }

    public function get_model() {
        return $this->model;
    }

    public function set_param( string $param, $value ) {
        $this->params[$param] = $value;
    }

    public function set_params( array $params ) {
        $this->params = $params;
    }

    public function get_params() {
        return $this->params;
    }

    public function version() {
        preg_match( "/gpt-(([0-9]+)\.?([0-9]+)?)/", $this->model, $matches );
        return floatval( $matches[1] );
    }

    public function force_tool_choice( $tool_choice ) {
        $this->tool_choice = $tool_choice;
    }

    public function smessage( string $system_message ) {
        $message = [
            "role" => "system",
            "content" => $system_message,
        ];

        $this->messages[] = $message;

        if( is_callable( $this->savefunction ) ) {
            ($this->savefunction)( (object) $message, $this->chat_id );
        }
    }

    public function umessage( string $user_message ) {
        $message = [
            "role" => "user",
            "content" => $user_message,
        ];

        $this->messages[] = $message;

        if( $this->assistant_mode ) {
            $this->add_assistants_message( $message );
        }

        if( is_callable( $this->savefunction ) ) {
            ($this->savefunction)( (object) $message, $this->chat_id );
        }
    }

    public function amessage( string $assistant_message ) {
        $message = [
            "role" => "assistant",
            "content" => $assistant_message,
        ];

        $this->messages[] = $message;

        if( is_callable( $this->savefunction ) ) {
            ($this->savefunction)( (object) $message, $this->chat_id );
        }
    }

    public function fresult(
        string $tool_call_id,
        string $function_return_value
    ) {
        $message = [
            "role" => "tool",
            "content" => $function_return_value,
            "tool_call_id" => $tool_call_id,
        ];

        $this->messages[] = $message;

        if( is_callable( $this->savefunction ) ) {
            ($this->savefunction)( (object) $message, $this->chat_id );
        }
    }

    public function assistant_response(
        bool $raw_function_response = false,
        ?StreamType $stream_type = null
    ) {
        if( $this->run !== null && $this->run->get_status() !== "requires_action" ) {
            $this->run = $this->create_run(
                $this->thread_id,
                $this->assistant->get_id(),
            );
        }

        while( true ) {
            usleep( 1000*100 );

            $this->run = $this->fetch_run(
                 $this->thread_id,
                $this->run->get_id()
            );

            if( ! $this->run->is_pending() ) {
                break;
            }
        }

        if( $this->run->get_status() === "requires_action" ) {
            $required_action = $this->run->get_required_action();

            if( $required_action["type"] !== "submit_tool_outputs" ) {
                throw new \Exception( "Unrecognized required action type '".$required_action["type"]."'" );
            }

            $message = new \stdClass;
            $message->role = "assistant";
            $message->content = null;
            $message->tool_calls = $required_action["submit_tool_outputs"]["tool_calls"];
        } else {
            $messages = $this->get_thread_messages(
                 $this->thread_id,
                 1,
                "desc",
            );

            $message = new \stdClass;
            $message->role = $messages[0]["role"];
            $message->content = $messages[0]["content"][0]["text"]["value"];
        }

        $message = $this->handle_functions( $message, $raw_function_response );

        return $message;
    }

    public function response_with_retry(int $max_retries = 3) {
        $retries = 0;
        $message = null;
        while ($retries < $max_retries) {
            try {
                return $this->response();
            } catch (\Exception $e) {
                $retries++;
                sleep(10);
                $message = $e->getMessage();
                echo "Failed attempt $retries: $message\n";
            }
        }
        throw new \Exception("Failed to get response after $max_retries retries. Last error: $message");
    }

    public function response(
        bool $raw_function_response = false,
        ?StreamType $stream_type = null
    ) {
        if( $this->assistant_mode ) {
            return $this->assistant_response(
                $raw_function_response,
                $stream_type, // TODO: streaming is not supported yet
            );
        }

        $params = [
            "model" => $this->model,
            "messages" => $this->messages,
        ];

        $params = array_merge( $params, $this->params );

        $functions = $this->get_functions();

        if( ! empty( $functions ) ) {
            $params["tools"] = $functions;
            $params["tool_choice"] = $this->tool_choice;
        }

        // make ChatGPT API request
        $ch = curl_init( "{$this->base_url}/chat/completions" );
        curl_setopt( $ch, CURLOPT_HTTPHEADER, [
            "Content-Type: application/json",
            "Authorization: Bearer " . $this->api_key
        ] );

        curl_setopt( $ch, CURLOPT_POST, true );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 10);

        if( $stream_type ) {
            $params["stream"] = true;

            $response_text = "";

            curl_setopt( $ch, CURLOPT_WRITEFUNCTION, function( $ch, $data ) use ( &$response_text, $stream_type ) {
                $response_text .= $this->parse_stream_data( $ch, $data, $stream_type );

                if( connection_aborted() ) {
                    return 0;
                }

                return strlen( $data );
            } );
        }

        curl_setopt( $ch, CURLOPT_POSTFIELDS, json_encode(
            $params
        ) );

        $curl_exec = curl_exec( $ch );

        // get ChatGPT reponse
        if( $stream_type ) {
            if( $stream_type === StreamType::Event ) {
                echo "event: stop\n";
                echo "data: stopped\n\n";
            }

            $message = new \stdClass;
            $message->role = "assistant";
            $message->content = $response_text;
        } else {
            $response = json_decode( $curl_exec );

            // somewhat handle errors
            if( ! isset( $response->choices[0]->message ) ) {
                if( isset( $response->error ) ) {
                    if (is_string($response->error)) {
                        $error = $response->error;
                    }
                    else {
                        $error = trim( $response->error->message . " (" . $response->error->type . ")" );
                    }
                } else {
                    $error = $curl_exec;
                }
                throw new \Exception( "Error in OpenAI request: " . $error );
            }

            // add response to messages
            $message = $response->choices[0]->message;
        }
        //print_r($message);

        $this->messages[] = $message;

        if( is_callable( $this->savefunction ) ) {
            ($this->savefunction)( (object) $message, $this->chat_id );
        }

        $message = end( $this->messages );

        $message = $this->handle_functions( $message, $raw_function_response );

        return $message;
    }

    public function stream( StreamType $stream_type ) {
        while( ob_get_level() ) ob_end_flush();
        return $this->response( false, $stream_type );
    }

    protected function parse_stream_data( $ch, string $data, StreamType $stream_type ): string {
        $json = json_decode( $data );

        if( isset( $json->error ) ) {
            $error  = $json->error->message;
            $error .= " (" . $json->error->code . ")";
            $error  = "`" . trim( $error ) . "`";

            if( $stream_type == StreamType::Event ) {
                echo "data: " . json_encode( ["content" => $error] ) . "\n\n";

                echo "event: stop\n";
                echo "data: stopped\n\n";
            } elseif( $stream_type == StreamType::Plain ) {
                echo $error;
            } else {
                echo $data;
            }

            flush();
            die();
        }

        $response_text = "";

        $deltas = explode( "\n", $data );

        foreach( $deltas as $delta ) {
            if( strpos( $delta, "data: " ) !== 0 ) {
                continue;
            }

            $json = json_decode( substr( $delta, 6 ) );

            if( isset( $json->choices[0]->delta ) ) {
                $content = $json->choices[0]->delta->content ?? "";
            } elseif( trim( $delta ) == "data: [DONE]" ) {
                $content = "";
            } else {
                error_log( "Invalid ChatGPT response: '" . $delta . "'" );
            }

            $response_text .= $content;

            if( $stream_type == StreamType::Event ) {
                echo "data: " . json_encode( ["content" => $content] ) . "\n\n";
            } elseif( $stream_type == StreamType::Plain ) {
                echo $content;
            } else {
                echo $data;
            }

            flush();
        }

        return $response_text;
    }

    protected function handle_functions( \stdClass $message, bool $raw_function_response = false ) {
        if( isset( $message->tool_calls ) ) {
            //print_r($message);
            $function_calls = array_filter(
                $message->tool_calls,
                fn( $tool_call ) => $tool_call->type === "function"
            );

            if( $raw_function_response ) {
                // for backwards compatibility
                if( count( $function_calls ) === 1 ) {
                    $message->function_call = $function_calls[0]["function"];
                }

                return $message;
            }

            $tool_outputs = [];

            foreach( $function_calls as $tool_call ) {
                // get function name and arguments
                $function_call = $tool_call->function;
                $function_name = $function_call->name;
                $arguments = json_decode( $function_call->arguments, true );

                // sometimes ChatGPT responds with only a string of the
                // first argument instead of a JSON object
                if( $arguments === null ) {
                    echo "Warning: Invalid JSON in function arguments: " . $function_call->arguments . "\n";
                    $arguments = [$function_call->arguments];
                }

                $callable = $this->get_function( $function_name );

                if( is_callable( $callable ) ) {
                    $result = $callable( ...array_values( $arguments ) );
                } else {
                    $result = "Function '$function_name' unavailable.";
                }

                $tool_outputs[$tool_call->id] = $result;

                $this->fresult( $tool_call->id, $result );
            }

            if( $this->assistant_mode ) {
                $this->submit_tool_outputs(
                    $this->thread_id,
                    $this->run->get_id(),
                    $tool_outputs,
                );
            }

            return $this->response();
        }

        return $message;
    }

    protected function get_function( string $function_name ) {
        if( $this->assistant_mode ) {
            $functions = $this->assistant->get_functions();
        } else {
            $functions = $this->functions;
        }

        foreach( $functions as $function ) {
            if( $function["name"] === $function_name ) {
                return $function["function"] ?? $function["name"];
            }
        }

        return false;
    }

    protected function get_functions( ?array $function_list = null ) {
        $tools = [];

        if( $function_list === null ) {
            $function_list = $this->functions;
        }

        foreach( $function_list as $function ) {
            $properties = [];
            $required = [];

            foreach( $function["parameters"] as $parameter ) {
                $properties[$parameter['name']] = [
                    "type" => $parameter['type'],
                    "description" => $parameter['description'],
                ];

                if( isset( $parameter["items"] ) ) {
                    $properties[$parameter['name']]["items"] = $parameter["items"];
                }

                if( array_key_exists( "required", $parameter ) && $parameter["required"] !== false ) {
                    $required[] = $parameter["name"];
                }
            }
            if (empty($properties)) {
                $properties = new \stdClass();
            }

            $tools[] = [
                "type" => "function",
                "function" => [
                    "name" => $function["name"],
                    "description" => $function["description"],
                    "strict" => true,
                    "parameters" => [
                        "type" => "object",
                        "properties" => $properties,
                        "required" => $required,
                        "additionalProperties"=> false
                    ],
                ],
            ];
        }

        return $tools;
    }

    public function add_function( callable $function ) {
        if( is_callable( $function, true ) ) {
            $function = $this->parse_function( $function );

            if( ! is_callable( $function['function'] ) ) {
                throw new \Exception( "Function must be callable (public)" );
            }
        }
        $this->functions[] = $function;
    }

    protected function parse_function(  $function ) {
        if( is_array( $function ) ) {
            if( ! is_callable( $function, true ) ) {
                throw new \Exception( "Invalid class method provided" );
            }

            $reflection = new \ReflectionMethod( ...$function );
        } else {
            $reflection = new \ReflectionFunction( $function );
        }

        $doc_comment = $reflection->getDocComment() ?: "";
        $description = $this->parse_description( $doc_comment );

        $function_data = [
            "function" => $function,
            "name" => $reflection->getName(),
            "description" => $description,
            "parameters" => [],
        ];

        $matches = [];
        preg_match_all( '/@param\s+(\S+)\s+\$(\S+)[^\S\r\n]?([^\r\n]+)?/', $doc_comment, $matches );

        $types = $matches[1];
        $names = $matches[2];
        $descriptions = $matches[3];

        $params = $reflection->getParameters();
        foreach( $params as $param ) {
            $name = $param->getName();
            $index = array_search( $name, $names );
            $description = $descriptions[$index] ?? "";
            $type = $param->getType() === null ? null: $param->getType()->getName() ?? $types[$index] ?? "string";

            try {
                $param->getDefaultValue();
                $required = false;
            } catch( \ReflectionException $e ) {
                $required = true;
            }

            $data = [
                "name" => $name,
                "type" => $this->parse_type( $type ),
                "description" => $description,
                "required" => $required,
            ];

            if( strpos( $type, "array<" ) === 0 ) {
                $array_type = trim( substr( $type, 5 ), "<>" );
                $data["type"] = "array";
                $data["items"] = [
                    "type" => $this->parse_type( $array_type ),
                ];
            }

            if( strpos( $type, "[]" ) !== false ) {
                $array_type = substr( $type, 0, -2 );
                $data["type"] = "array";
                $data["items"] = [
                    "type" => $this->parse_type( $array_type ),
                ];
            }

            $function_data["parameters"][] = $data;
        }

        return $function_data;
    }

    protected function parse_type( string $type ) {
        switch ( $type ) {
            case "int":
            case "float":
            case "integer":
                return "number";
            default:
                return "string";
        }
    }

    protected function parse_description( string $doc_comment ) {
        $lines = explode( "\n", $doc_comment );
        $description = "";

        $started = false;
        foreach( $lines as $line ) {
            $matches = [];
            if( preg_match( '/\s+?\*\s+?([^@](.*?))?$/', $line, $matches ) === 1 ) {
                $description .= " ".$matches[1];
                $started = true;
            } elseif( $started ) {
                break;
            }
        }

        return trim( $description );
    }

    public function messages() {
        return $this->messages;
    }

    public function loadfunction( callable $loadfunction, bool $autoload = true ) {
        $this->loadfunction = $loadfunction;
        if( $autoload && ! $this->loaded ) {
            $this->load();
        }
    }

    public function savefunction( callable $savefunction ) {
        $this->savefunction = $savefunction;
    }

    protected function openai_api_post(
        string $url,
        $postfields = "",
        array $extra_headers = [],
        bool $post = true
    ) {
        $ch = curl_init( $url );

        $headers = [
            "Content-Type: application/json",
            "Authorization: Bearer " . $this->api_key,
            ...$extra_headers,
        ];

        curl_setopt( $ch, CURLOPT_HTTPHEADER, $headers );

        curl_setopt( $ch, CURLOPT_POST, $post );
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );

        if( $post ) {
            curl_setopt( $ch, CURLOPT_POSTFIELDS, $postfields );
        }

        $response = curl_exec( $ch );

        curl_close( $ch );

        $data = json_decode( $response, true );

        if( ! isset( $data["id"] ) && ! isset( $data["data"] ) ) {
            if( isset( $data["error"] ) ) {
                throw new \Exception( "Error in OpenAI request: " . $data["error"]["message"] );
            }

            throw new \Exception( "Error in OpenAI request: " . $data );
        }

        return $data;
    }

    public function create_assistant(
        string $model,
        string $name = "",
        string $instructions = "",
        array $functions = []
    ) {
        foreach( $functions as $i => $function ) {
            $functions[$i] = $this->parse_function( $function );
        }

        $tools = $this->get_functions( $functions );

        $response = $this->openai_api_post(
            "{$this->base_url}/assistants",
            json_encode( [
                "model" => $model,
                "name" => $name,
                "instructions" => $instructions,
                "tools" => $tools,
            ],
                ["OpenAI-Beta: assistants=v1"])
        );

        /*return new Assistant(
            name: $response["name"],
            model: $response["model"],
            tools: $response["tools"],
            id: $response["id"],
        );*/
    }

    public function create_thread() {
/*        $response = $this->openai_api_post(
            url: "{$this->base_url}/threads",
            extra_headers: ["OpenAI-Beta: assistants=v1"],
        );

        return new Thread(
            id: $response["id"],
        );*/
    }

    public function create_run(
        string $thread_id,
        string $assistant_id
    ) {
/*        $response = $this->openai_api_post(
            url: "{$this->base_url}/threads/".$thread_id."/runs",
            extra_headers: ["OpenAI-Beta: assistants=v1"],
            postfields: json_encode( [
                "assistant_id" => $assistant_id,
            ] )
        );

        return new Run(
            thread_id: $thread_id,
            required_action: $response["required_action"] ?? null,
            status: $response["status"],
            id: $response["id"],
        );*/
    }

    public function fetch_run(
        string $thread_id,
        string $run_id
    ) {
/*        $response = $this->openai_api_post(
            url: "{$this->base_url}/threads/" . $thread_id . "/runs/" . $run_id,
            extra_headers: ["OpenAI-Beta: assistants=v1"],
            post: false,
        );

        return new Run(
            thread_id: $thread_id,
            required_action: $response["required_action"] ?? null,
            status: $response["status"],
            id: $response["id"],
        );*/
    }

    public function fetch_assistant( string $assistant_id ) {
/*        $response = $this->openai_api_post(
            url: "{$this->base_url}/assistants/" . $assistant_id,
            extra_headers: ["OpenAI-Beta: assistants=v1"],
            post: false,
        );

        return new Assistant(
            model: $response["model"],
            id: $response["id"],
            tools: $response["tools"],
            name: $response["name"],
        );*/
    }

    public function get_thread_messages(
        string $thread_id,
        int $limit,
        string $order = "asc"
    ) {
/*        $response = $this->openai_api_post(
            url: "{$this->base_url}/threads/" . $thread_id . "/messages?limit=" . $limit . "&order=" . $order,
            extra_headers: ["OpenAI-Beta: assistants=v1"],
            post: false,
        );

        return $response["data"];*/
    }

    public function add_assistants_message(
        array $message
    ): void {
/*        $this->openai_api_post(
            url: "{$this->base_url}/threads/" . $this->thread_id . "/messages",
            extra_headers: ["OpenAI-Beta: assistants=v1"],
            postfields: json_encode( [
                "role" => $message["role"],
                "content" => $message["content"],
            ] )
        );*/
    }

    public function submit_tool_outputs(
        string $thread_id,
        string $run_id,
        array $tool_call_outputs
    ): void {
        $tool_outputs = [];

        foreach( $tool_call_outputs as $tool_call_id => $tool_call_output ) {
            $tool_outputs[] = [
                "tool_call_id" => $tool_call_id,
                "output" => $tool_call_output,
            ];
        }

        $this->openai_api_post(
            "{$this->base_url}/threads/".$thread_id."/runs/".$run_id."/submit_tool_outputs",
            json_encode( [
                "tool_outputs" => $tool_outputs
            ] ,
                ["OpenAI-Beta: assistants=v1"],)
        );
    }

    public function getBaseUrl(): string
    {
        return $this->base_url;
    }

    public function setBaseUrl(string $base_url): void
    {
        $this->base_url = $base_url;
    }
}