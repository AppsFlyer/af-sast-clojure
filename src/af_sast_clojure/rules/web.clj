(ns af_sast_clojure.rules.web
  (:gen-class)
  (:require
    [clojure.spec.alpha :as s]
    [grasp.api :as g]
    [af_sast_clojure.helpers :as h]))

(def routes-rule
  {
   :level       "info"
   :message     (fn [form meta]
                  {
                   :text      "Found Web Route - {0} {1}"
                   :arguments [
                               (str (first form))
                               (str (fnext form))
                               ]
                   }
                  )
   :fingerprint h/method-and-first-arg-hash
   :category    "web"
   :kind        "informational"
   :spec        (g/seq (s/and symbol?
                              #(let [symbol %
                                     symbol_name (name symbol)
                                     resolved (g/resolve-symbol symbol)]

                                 ; Not always works see - https://github.com/borkdude/grasp/issues/14
                                 (or (contains? #{
                                                  'compojure.core/GET
                                                  'compojure.core/POST
                                                  'compojure.core/PUT
                                                  'compojure.core/PATCH
                                                  'compojure.core/DELETE
                                                  'compojure.core/OPTIONS
                                                  'compojure.core/ANY
                                                  } resolved)
                                     (and
                                       (contains? #{
                                                    "GET"
                                                    "POST"
                                                    "PUT"
                                                    "PATCH"
                                                    "DELETE"
                                                    "OPTIONS"
                                                    "ANY"
                                                    } symbol_name
                                                  )))
                                 ))
                       (s/+ any?))
   :rule        "CLJ-SEC-ROUTE"
   })

