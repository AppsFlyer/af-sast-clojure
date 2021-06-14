(ns af_sast_clojure.rules.execution
  (:gen-class)
  (:require
    [clojure.spec.alpha :as s]
    [grasp.api :as g]
    [af_sast_clojure.helpers :as h]
    [digest]
    [clojure.string :as string]))

(def read-string-rule
  {
   :level       "error"
   :message     (fn [form meta]
                  {
                   :text      (string/join "\n\t"
                                           [
                                            "Found {0} - This may execute {1} if not validated properly."
                                            "Please use another function or change to (clojure.edn/read-string) if you must read edn files"
                                            "See for more information - https://github.com/AppsFlyer/af-sast-clojure/blob/master/doc/READ-STRING.md"
                                            ]

                                           )
                   :arguments [
                               (str (first form))
                               (str (fnext form))
                               ]
                   }
                  )
   :fingerprint h/calc-form-hash
   :category    "execution"
   :kind        "fail"
   :spec        (h/with-skip
                  (g/seq
                    (h/has-symbol #{
                                    'RT/readString
                                    'clojure.core/load-file
                                    'clojure.core/load-string
                                    'clojure.core/load-reader
                                    'clojure.core/read
                                    'clojure.core/read-string
                                    })
                    ; Skip Static string arguments
                    (h/not-static-string)
                    ))

   :rule        "CLJ-SEC-READ-STRING"
   })
