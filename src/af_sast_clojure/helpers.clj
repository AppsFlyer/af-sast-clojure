(ns af_sast_clojure.helpers
  (:require [digest]
            [clojure.spec.alpha :as s]
            [grasp.api :as g]))

(defn calc-form-hash [form meta]
  {:formHash/v1 (digest/digest "sha-1" (str form))}
  )

(defn method-and-first-arg-hash [form meta]
  {:methodHash/v1 (digest/digest "sha-1"
                                 (clojure.string/join " " (take 2 form))
                                 )}
  )

(def skip_forms (atom ()))

(defn with-skip
  "Use this macro to make spec skippable"
  [orig-spec]
  (s/and
    (fn [input]
      (when (= "allow-security"
               (and (seq? input)
                    (symbol? (first input))
                    (name (first input))
                    ))
        (swap! skip_forms conj (second input))
        )
      true
      )
    orig-spec
    )
  )

(defn has-symbol [symbols]
  (s/and symbol?
         (fn [symbol]
           (let [resolved (g/resolve-symbol symbol)]
             (contains? symbols resolved))))
  )

(defn has-symbol-name [symbols]
  (s/and symbol?
         (fn [symbol]
           (let [resolved (name symbol)]
             (contains? symbols resolved))))
  )

(defn has-text [text]
  (fn [form]
    (let [str_form (str form)]
      (clojure.string/includes? str_form text)
      )
    )
  )

(defn print_spec [comment]
  (fn [x]
    (println comment x)
    true
    )
  )

(defn any []
  (constantly true)
  )

(defn not-static-string []
  (complement string?)
  )


