(ns af_sast_clojure.rules.debug
  (:gen-class)
  (:require
    [clojure.spec.alpha :as s]
    [grasp.api :as g]
    [af_sast_clojure.helpers :as h]
    [digest]
    ))


(def debug
  {
   :level       "error"
   :message     (fn [form meta]
                  {
                   :text      "Debug {0}"
                   :arguments [
                               (str form)
                               ]
                   }
                  )
   :fingerprint h/calc-form-hash
   :category    "execution"
   :kind        "fail"
   :spec
                (h/with-skip
                  (s/and
                    (h/print_spec "Main")
                    (g/seq
                      (h/print_spec "1")
                      (h/print_spec "2")
                      (h/print_spec "3")
                      )
                    ;(constantly false)
                    )
                  )
   :rule        "CLJ-SEC-DEBUG"
   })
