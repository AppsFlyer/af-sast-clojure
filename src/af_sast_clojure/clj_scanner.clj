(ns af_sast_clojure.clj-scanner

  (:gen-class)
  (:require [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [clojure.string :as str]
            [cheshire.core :as cheshire]
            [grasp.api :as g]
            [clj-time.core :as t]
            [clj-time.format :as f]
            [af_sast_clojure.rules.execution :refer [read-string-rule]]
            [af_sast_clojure.rules.java_danger :refer [java-rule]]
            [af_sast_clojure.rules.web :refer [routes-rule]]
            [clojure.tools.cli :refer [parse-opts]]
            [clojure.string :as string]
            [af_sast_clojure.helpers :as h])
  (:import (java.util UUID)
           (java.nio.file Paths)))

(def built-in-formatter (f/formatter "yyyy-mm-dd'T'hh:mm:ss"))

(defn getPath [url]
  (Paths/get (.toURI (io/file url)))
  )

(def rules
  [
   read-string-rule
   java-rule
   routes-rule
   ]
  )

(def results (atom []))
(def error-log (io/file (System/getProperty "java.io.tmpdir") "assoc_pairs_errors.txt"))
(def errors? (atom false))
(defn write-errors [s]
  (when-not (str/blank? s)
    (reset! errors? true)
    (locking error-log
      (spit error-log s :append true))))

(def progress-indicator (cycle ["-" "\\" "|" "/"]))

(defn grasp-task [^java.util.concurrent.LinkedBlockingDeque deque cli_rule]
  (loop []
    (when-let [[file progress] (.pollFirst deque)]
      (try
        (binding [*out* *err*]
          (print (str "\r" progress)) (flush))
        (let [errors (java.io.StringWriter.)]
          (binding [*err* errors]
            (doseq [{:keys [:spec :rule] :as full_rule} rules]
              (when (or (nil? cli_rule) (= cli_rule rule))
                (let [
                      found (g/grasp file spec)
                      found_with (map #(assoc (dissoc full_rule :spec) :form %) found)
                      ]
                  (swap! results conj (doall found_with))))
              ))
          (write-errors (str errors)))
        (catch Exception e (binding [*out* *err*]
                             (prn e))))
      (recur))))

(defn regular-grasp [files cli_rule]
  (doseq [file files]
    (doseq [{:keys [:spec :rule] :as full_rule} rules]
      (when (or (nil? cli_rule) (= cli_rule rule))
        (let [
              found (g/grasp file spec)
              found_with (map #(assoc (dissoc full_rule :spec) :form %) found)

              valid_found (filter (fn [{:keys [:form]}]
                                    (nil? (some (fn [x]
                                                  (= (str x) (str form))
                                                  ) @h/skip_forms))
                                    ) found_with)
              ]
          (swap! results conj (doall valid_found))))
      ))
  )

(defn parallel-grasp [files cli_rule]
  (let [files-and-progress (map (fn [file progress]
                                  [file progress])
                                files progress-indicator)
        deque (java.util.concurrent.LinkedBlockingDeque. ^java.util.List files-and-progress)
        cnt (+ 2 (int (* 0.6 (.. Runtime getRuntime availableProcessors))))
        latch (java.util.concurrent.CountDownLatch. cnt)
        es (java.util.concurrent.Executors/newFixedThreadPool cnt)]
    (dotimes [_ cnt]
      (.execute es
                (bound-fn []
                  (grasp-task deque cli_rule)
                  (.countDown latch))))
    (.await latch)
    (.shutdown es)))

(defn remove-file-url [url]
  (clojure.string/replace url #"^file:" "")
  )

(defn clean-url [url base]
  (if (some? url)
    (let [base_url (getPath base)
          full_url (getPath (remove-file-url url))
          relative_url (.relativize base_url full_url)
          ]
      (str relative_url)
      )
    ""
    )
  )



(defn sarifResults [results opts]
  (map (fn [{:keys [:form :rule :message :level :kind :fingerprint] :as result}]
         (let [{:keys [:line :column :url] :as meta} (meta form)]
           {
            :level               level
            :ruleId              rule
            :kind                kind
            :message             (if (fn? message)
                                   (message form meta)
                                   {
                                    :text message
                                    }
                                   )
            :partialFingerprints (if (fn? fingerprint)
                                   (fingerprint form meta)
                                   {}
                                   )

            :locations           [{:physicalLocation {
                                                      :snippet          {
                                                                         :text (str form)
                                                                         }
                                                      :region           {
                                                                         :startLine   line
                                                                         :startColumn column
                                                                         }
                                                      :artifactLocation {
                                                                         :uri (clean-url url (:dir opts))
                                                                         }}}]

            }
           ))
       results))

(defn sarifGenerator [results opts]
  {
   :version "2.1.0"
   :$schema "http://json.schemastore.org/sarif-2.1.0-rtm.5"
   :runs    [{
              :tool    {
                        :driver {
                                 :name           "ClojureSecurityScanner"
                                 :informationUri "https://github.com"
                                 :version        "0.0.1"
                                 }
                        }

              :results (sarifResults results opts)
              }]}
  )

(defn uniqueFingerprint [result]
  ; TODO - Make real unique id
  (UUID/randomUUID)
  )


(defn gitlabResults [results opts]
  (map (fn [{:keys [:form :rule :message :level :category] :as result}]
         (let [{:keys [:line :column :url] :as meta} (meta form)]
           {
            :id                      (uniqueFingerprint result)
            :category                category
            :name                    rule
            :message                 (if (fn? message)
                                       (message form meta)
                                       message
                                       )
            :description             ""
            :cve                     ""
            :severity                "Info"
            ;              "Info",
            ;              "Unknown",
            ;              "Low",
            ;              "Medium",
            ;              "High",
            ;              "Critical"
            :confidence              "Unknown"
            :raw_source_code_extract (str form)
            :scanner                 {:id   "ClojureSecurityScanner"
                                      :name "ClojureSecurityScanner"}
            :location                {
                                      :file       (clean-url url (:dir opts))
                                      :start_line line
                                      :end_line   line
                                      :class      ""
                                      :method     ""

                                      }
            :identifiers             [
                                      {
                                       :type  rule
                                       :name  rule
                                       :value rule
                                       }
                                      ]

            }
           ))
       results))

(defn message_to_text [in_msg form]
  (let [object_message (if (fn? in_msg)
                         (in_msg form (meta form))
                         {:text in_msg}
                         )
        text_message (:text object_message)
        x (if-let [args (:arguments object_message)]
            (reduce (fn [msg [i value]]
                      (string/replace msg (str "{" i "}") value)
                      ) text_message (map-indexed vector args))
            text_message
            )
        ]
    x
    )
  )

(defn outGenerator [results {:keys [:routes :info :dir] :as opts}]
  (let [out (map (fn [{:keys [:rule :message :form :kind] :as result}]
                   (when (or info
                             (= "fail" kind))
                     (let [
                           {:keys [:url :line :column]} (meta form)
                           ci_url (System/getenv "CI_PROJECT_URL")
                           code_url (if (some? ci_url)
                                      (str ci_url "/blob/master/" (clean-url url dir) "#L")
                                      (remove-file-url url))
                           ]
                       (if routes
                         (message_to_text message form)
                         (str code_url ":" line "\n"
                              "\t" rule "\n"
                              "\t" (message_to_text message form) "\n"
                              "\t" "---" "\n"
                              "\t" (str form) "\n\n"))
                       )))
                 results)]

    (string/join "\r\n" out)
    )
  )
(defn gitlabGenerator [results {:keys [:start_time :end_time :dir] :as opts}]
  {
   :version         "3.0.0"
   :remediations    []
   :scan            {:scanner    {:id      "ClojureSecurityScanner"
                                  :name    "ClojureSecurityScanner"
                                  :url     "https://github.com"
                                  :vendor  {:name "AppsFlyer"}
                                  :version "v0.0.1"
                                  }
                     :type       "sast"
                     :start_time start_time
                     :end_time   end_time
                     :status     "success"
                     }
   :vulnerabilities (gitlabResults results opts)
   }
  )


(defn report! [results {:keys [:type :start_time :end_time] :as opts}]
  (if (= "cli" type)
    (outGenerator results opts)
    (let [
          generator (case type
                      "sarif" sarifGenerator
                      "gitlab" gitlabGenerator
                      sarifGenerator
                      )
          ]
      (-> results
          (generator opts)
          (cheshire/generate-string {:pretty true})))))

(def cli-options
  [["-t" "--type <sarif|gitlab|cli>" "Output type"
    :default "gitlab"]
   ["-d" "--dir <source_dir/file>" "Source Dir / file"
    :default (or (System/getenv "CI_PROJECT_DIR")
                 (str (.normalize (.toAbsolutePath (getPath "."))))
                 )]
   ["-o" "--output <file>" "Output Location"
    :default nil]
   ["-f" "--fail <false>" "Should it fail if vuln found"
    :default true]
   ["-r" "--rule <RULE>" "Specific rule"
    :default nil]
   ["-i" "--info" "Show information"
    :default nil]
   [nil "--routes" "Shows routes"
    :default false]
   ["-h" "--help"]])


(defn usage [options-summary]
  (->> ["Clojure Security Scanner"
        ""
        "Usage: clj-scanner [options]"
        ""
        "Options:"
        options-summary
        ""
        "Please refer to the Readme page for more information."]
       (string/join \newline)))

(defn -main [& args]
  (let [
        cli_opts (clojure.tools.cli/parse-opts args cli-options)
        start_time (f/unparse built-in-formatter (t/now))
        dir (get-in cli_opts [:options :dir])
        help? (get-in cli_opts [:options :help])
        output_type (get-in cli_opts [:options :type])
        cli_rule (get-in cli_opts [:options :rule])
        routes (get-in cli_opts [:options :routes])
        info (get-in cli_opts [:options :info])
        output (some->> (get-in cli_opts [:options :output])
                        (io/file dir)
                        )

        files (filter #(or
                         ;(str/ends-with? % ".jar")
                         (str/ends-with? % ".clj")
                         (str/ends-with? % ".cljc")
                         (str/ends-with? % ".cljs"))
                      (file-seq (io/file dir)))]
    (if help?
      (println (usage (:summary cli_opts)))
      (do
        (regular-grasp files cli_rule)
        ;(parallel-grasp files cli_rule)
        (print "\r")
        (flush)
        (when @errors?
          (binding [*out* *err*]
            (println "Logged errors to" (.getPath error-log))))

        (let [results (mapcat identity @results)
              report (report! results (merge (:options cli_opts) {
                                              :start_time start_time
                                              :end_time   (f/unparse built-in-formatter (t/now))
                                              }))
              should_fail_result (some (fn [result]
                                         (= "fail" (:kind result))
                                         ) results)
              ]

          (println (outGenerator results (:options cli_opts)))
          (when-some [out_file output]
            (spit out_file report))
          ;(when-not should_fail_result
          ;  (println "All is good")
          ;  )
          (System/exit (if should_fail_result 1 0))
          )
        )
      )
    )
  )
