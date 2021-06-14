# Clojure Security Scanner

Basic Security Scanner for Clojure

## Usage

Run the scanner directly:

    clj-scanner
    
    clj-scanner -d ./src/target


## Development 

Run the project directly:

    $ clojure -M -m af_sast_clojure.clj-scanner <DIR_TO_SCAN>

Run the project's tests:

    $ clojure -M:test:runner 

Build an uberjar:

    $ clojure -M:uberjar

Run that uberjar:

    $ java -jar security-scanner.jar <DIR_TO_SCAN>
    
Run with docker:

    $ docker run -it -v $(pwd):/scan clj-scanner -d scan
   
## Options

      -t, --type <sarif|gitlab>  gitlab                Output type
      -d, --dir <source_dir>     $(pwd)                Source Dir
      -o, --output <file>        gl-sast-report.json   Output Location
      -f, --fail <false>         true                  Should it fail if vuln found
      -r, --rule <RULE>          nil                   Specific rule
      -h, --help

## Examples

    clj-scanner -t gitlab -o gl-sast-report.json -f true -r CLJ-SEC-READ-STRING

## Thanks

Special thanks for Michiel Borkent (borkdude) for creating the grasp api this module relies on. 

Special thanks to Rotem Bar (irotem) for his work on this scanner. 

## License

Distributed under the Eclipse Public License version 1.0
