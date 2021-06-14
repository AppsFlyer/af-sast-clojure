(ns samples.read-string
  (:import
    (clojure.lang LispReader RT)))

(let [x (java.lang.Runtime/getRuntime)]
  (.exec x "ls")
  )

(.exec (Runtime/getRuntime) "ls")

(. (Runtime/getRuntime) exec (str "x" "ls -l"))

(defn allow-security [fn & rest]
      (eval fn))

(read-string (str "4"))

(allow-security
  (read-string (str "1"))
  "This is a test and we allow it"
  )

(RT/readString (str "2"))
(read-string "3") ;; <- should not be reported




