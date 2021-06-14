(ns af_sast_clojure.rules.java_danger
  (:gen-class)
  (:require
    [clojure.spec.alpha :as s]
    [grasp.api :as g]
    [af_sast_clojure.helpers :as h]
    [digest]
    ))


(def java-rule
  {
   :level       "error"
   :message     (fn [form meta]
                  {
                   :text      (str "Found Java Execution function {0} \n\tPlease refrain from using such functions and validate properly their usage\n")
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
                  (g/or
                    ; (.exec (Runtime/getRuntime) "ls")
                    (g/seq
                      (h/has-symbol-name #{".exec"})
                      (h/has-text "getRuntime")
                      (h/not-static-string)
                      )
                    ; (. (Runtime/getRuntime) exec "ls")
                    (g/seq
                      (h/has-symbol-name #{"."})
                      (h/has-text "getRuntime")
                      (h/has-symbol-name #{"exec"})
                      (h/not-static-string)
                      )
                    )
                  )
   :rule        "CLJ-SEC-JAVA-DANGER"
   })
