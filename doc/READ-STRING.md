# Code Execution

Code Execution is a vulnerability which allows attackers to execute code on the server from remote.
We can split code execution into two parts:
1. Execution of system commands through insecure usage of process invocation
1. Execution of source code usually by reflection or REPL usage

In Appsflyer as we are using dynamic languages it is very important to be aware of these types of attacks as they can easily happen

### Impact
Allowing code execution in system or code will allow an attacker to perform with the same permissions and access that the application has.
This means that the attacker will have the same permissions to the filesystem, network, secret management and other systems accessible by the application.

Example of vulnerable code

Read-String invocation
```clojure
(let [currency input_from_user]
   (clojure.core/read-string currency)
)
```

Shell Invocation
```clojure
(sh "openssl" "pkcs12" "-export" "-in" 
    (str pem-file) "-inkey" 
    (str key-file) "-out" 
    (str p12_temp_file) "-passout" "pass:appsflyer")
```

### How to fix the code?
Whenever using dynamic code we need to think first of all if it is really needed, most cases can be solved in more secure ways.

If there is still a need to use dynamic invocation of code with strings that come from dynamic inputs we should use clojure.edn/read-string or other libraries that are execution safe.

Last resort is to sanitize all input to be constrained as possible - enum,  length, charset, regex, ....
