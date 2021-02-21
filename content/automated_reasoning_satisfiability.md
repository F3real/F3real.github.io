Title: Automated Reasoning: satisfiability
Date: 2021-2-21 10:01
Modified: 2021-2-21 10:01
Category: misc
Tags: z3
Slug: automated_reasoning_satisfiability
Authors: F3real
Summary: Automated Reasoning z3 exercise solution

The course `Automated Reasoning: satisfiability` from EIT Digital offered on Coursera had following exercise to be solved in z3.


>Question 1
>Eight trucks have to deliver pallets of obscure building blocks to a magic factory. Every truck has a capacity of 8000 kg and can carry at most eight pallets.  In total, the following has to be delivered:
>
>•Four pallets of nuzzles, each of weight 800 kg.
>
>•A number of pallets of prittles, each of weight 1100 kg.
>
>•Eight pallets of skipples, each of weight 1000 kg.
>
>•Ten pallets of crottles, each of weight 2500 kg.
>
>•Twenty pallets of dupples, each of weight 200 kg.
>
>Skipples need to be cooled; only three of the eight trucks have the facility for cooling skipples.
>
>Nuzzles are very valuable; to distribute the risk of loss no two pallets of nuzzles may be in the same truck.
>
>Investigate what is the maximum number of pallets of prittles that can be delivered.
>
>Question 2
>Consider all requirements from Question 1, but now with the following  addtional requirement.
>
>Prittles and crottles are an explosive combination: they are not allowed to be put in the same truck.
>
>Again, investigate what is the maximum number of pallets of prittles that can be delivered.


The solution can be generated (and it is actually recomended to do so) with script, but I just wrote pure z3 version.
Here is the code for those interested:

~~~
(declare-const truck_1 Int)
(declare-const truck_2 Int)
(declare-const truck_3 Int)
(declare-const truck_4 Int)
(declare-const truck_5 Int)
(declare-const truck_6 Int)
(declare-const truck_7 Int)
(declare-const truck_8 Int)

(declare-const truck_1_nuzzles Int)
(declare-const truck_2_nuzzles Int)
(declare-const truck_3_nuzzles Int)
(declare-const truck_4_nuzzles Int)
(declare-const truck_5_nuzzles Int)
(declare-const truck_6_nuzzles Int)
(declare-const truck_7_nuzzles Int)
(declare-const truck_8_nuzzles Int)

(declare-const number_nuzzles Int)
(declare-const nuzzles_weight Int)

(declare-const truck_1_skipples Int)
(declare-const truck_2_skipples Int)
(declare-const truck_3_skipples Int)
(declare-const truck_4_skipples Int)
(declare-const truck_5_skipples Int)
(declare-const truck_6_skipples Int)
(declare-const truck_7_skipples Int)
(declare-const truck_8_skipples Int)

(declare-const number_skipples Int)
(declare-const skipples_weight Int)

(declare-const truck_1_prittles Int)
(declare-const truck_2_prittles Int)
(declare-const truck_3_prittles Int)
(declare-const truck_4_prittles Int)
(declare-const truck_5_prittles Int)
(declare-const truck_6_prittles Int)
(declare-const truck_7_prittles Int)
(declare-const truck_8_prittles Int)

(declare-const number_prittles Int)
(declare-const prittles_weight Int)

(declare-const truck_1_crottles Int)
(declare-const truck_2_crottles Int)
(declare-const truck_3_crottles Int)
(declare-const truck_4_crottles Int)
(declare-const truck_5_crottles Int)
(declare-const truck_6_crottles Int)
(declare-const truck_7_crottles Int)
(declare-const truck_8_crottles Int)

(declare-const number_crottles Int)
(declare-const crottles_weight Int)

(declare-const truck_1_dupples Int)
(declare-const truck_2_dupples Int)
(declare-const truck_3_dupples Int)
(declare-const truck_4_dupples Int)
(declare-const truck_5_dupples Int)
(declare-const truck_6_dupples Int)
(declare-const truck_7_dupples Int)
(declare-const truck_8_dupples Int)

(declare-const number_dupples Int)
(declare-const dupples_weight Int)

; nuzzles
(assert (>= truck_1_nuzzles 0))
(assert (>= truck_2_nuzzles 0))
(assert (>= truck_3_nuzzles 0))
(assert (>= truck_4_nuzzles 0))
(assert (>= truck_5_nuzzles 0))
(assert (>= truck_6_nuzzles 0))
(assert (>= truck_7_nuzzles 0))
(assert (>= truck_8_nuzzles 0))

(assert (< truck_1_nuzzles 2))
(assert (< truck_2_nuzzles 2))
(assert (< truck_3_nuzzles 2))
(assert (< truck_4_nuzzles 2))
(assert (< truck_5_nuzzles 2))
(assert (< truck_6_nuzzles 2))
(assert (< truck_7_nuzzles 2))
(assert (< truck_8_nuzzles 2))

(assert (= number_nuzzles 4))
(assert (= nuzzles_weight 800))
(assert (= number_nuzzles (+ truck_1_nuzzles truck_2_nuzzles truck_3_nuzzles truck_4_nuzzles truck_5_nuzzles truck_6_nuzzles truck_7_nuzzles truck_8_nuzzles)))

; prittles
(assert (>= truck_1_prittles 0))
(assert (>= truck_2_prittles 0))
(assert (>= truck_3_prittles 0))
(assert (>= truck_4_prittles 0))
(assert (>= truck_5_prittles 0))
(assert (>= truck_6_prittles 0))
(assert (>= truck_7_prittles 0))
(assert (>= truck_8_prittles 0))

(assert (= prittles_weight 1100))
(assert (= number_prittles (+ truck_1_prittles truck_2_prittles truck_3_prittles truck_4_prittles truck_5_prittles truck_6_prittles truck_7_prittles truck_8_prittles)))

; skipples
(assert (>= truck_1_skipples 0))
(assert (>= truck_2_skipples 0))
(assert (>= truck_3_skipples 0))
(assert (= truck_4_skipples 0))
(assert (= truck_5_skipples 0))
(assert (= truck_6_skipples 0))
(assert (= truck_7_skipples 0))
(assert (= truck_8_skipples 0))

(assert (= number_skipples 8))
(assert (= skipples_weight 1000))
(assert (= number_skipples (+ truck_1_skipples truck_2_skipples truck_3_skipples truck_4_skipples truck_5_skipples truck_6_skipples truck_7_skipples truck_8_skipples)))

; crottles
(assert (>= truck_1_crottles 0))
(assert (>= truck_2_crottles 0))
(assert (>= truck_3_crottles 0))
(assert (>= truck_4_crottles 0))
(assert (>= truck_5_crottles 0))
(assert (>= truck_6_crottles 0))
(assert (>= truck_7_crottles 0))
(assert (>= truck_8_crottles 0))

(assert (= number_crottles 10))
(assert (= crottles_weight 2500))
(assert (= number_crottles (+ truck_1_crottles truck_2_crottles truck_3_crottles truck_4_crottles truck_5_crottles truck_6_crottles truck_7_crottles truck_8_crottles)))

; dupples
(assert (>= truck_1_dupples 0))
(assert (>= truck_2_dupples 0))
(assert (>= truck_3_dupples 0))
(assert (>= truck_4_dupples 0))
(assert (>= truck_5_dupples 0))
(assert (>= truck_6_dupples 0))
(assert (>= truck_7_dupples 0))
(assert (>= truck_8_dupples 0))

(assert (= number_dupples 20))
(assert (= dupples_weight 200))
(assert (= number_dupples (+ truck_1_dupples truck_2_dupples truck_3_dupples truck_4_dupples truck_5_dupples truck_6_dupples truck_7_dupples truck_8_dupples)))

(assert (= truck_1 8000))
(assert (= truck_2 8000))
(assert (= truck_3 8000))
(assert (= truck_4 8000))
(assert (= truck_5 8000))
(assert (= truck_6 8000))
(assert (= truck_7 8000))
(assert (= truck_8 8000))

(assert (>= truck_1 
(+
(* nuzzles_weight truck_1_nuzzles)
(* prittles_weight truck_1_prittles)
(* skipples_weight truck_1_skipples)
(* crottles_weight truck_1_crottles)
(* dupples_weight truck_1_dupples)
)))
(assert (>= truck_2 
(+
(* nuzzles_weight truck_2_nuzzles)
(* prittles_weight truck_2_prittles)
(* skipples_weight truck_2_skipples)
(* crottles_weight truck_2_crottles)
(* dupples_weight truck_2_dupples)
)))
(assert (>= truck_3 
(+
(* nuzzles_weight truck_3_nuzzles)
(* prittles_weight truck_3_prittles)
(* skipples_weight truck_3_skipples)
(* crottles_weight truck_3_crottles)
(* dupples_weight truck_3_dupples)
)))
(assert (>= truck_4 
(+
(* nuzzles_weight truck_4_nuzzles)
(* prittles_weight truck_4_prittles)
(* skipples_weight truck_4_skipples)
(* crottles_weight truck_4_crottles)
(* dupples_weight truck_4_dupples)
)))
(assert (>= truck_5 
(+
(* nuzzles_weight truck_5_nuzzles)
(* prittles_weight truck_5_prittles)
(* skipples_weight truck_5_skipples)
(* crottles_weight truck_5_crottles)
(* dupples_weight truck_5_dupples)
)))
(assert (>= truck_6 
(+
(* nuzzles_weight truck_6_nuzzles)
(* prittles_weight truck_6_prittles)
(* skipples_weight truck_6_skipples)
(* crottles_weight truck_6_crottles)
(* dupples_weight truck_6_dupples)
)))
(assert (>= truck_7 
(+
(* nuzzles_weight truck_7_nuzzles)
(* prittles_weight truck_7_prittles)
(* skipples_weight truck_7_skipples)
(* crottles_weight truck_7_crottles)
(* dupples_weight truck_7_dupples)
)))
(assert (>= truck_8 
(+
(* nuzzles_weight truck_8_nuzzles)
(* prittles_weight truck_8_prittles)
(* skipples_weight truck_8_skipples)
(* crottles_weight truck_8_crottles)
(* dupples_weight truck_8_dupples)
)))

(assert (>= 8 
(+ truck_1_nuzzles truck_1_prittles truck_1_skipples truck_1_crottles truck_1_dupples)
))
(assert (>= 8 
(+ truck_2_nuzzles truck_2_prittles truck_2_skipples truck_2_crottles truck_2_dupples)
))
(assert (>= 8 
(+ truck_3_nuzzles truck_3_prittles truck_3_skipples truck_3_crottles truck_3_dupples)
))
(assert (>= 8 
(+ truck_4_nuzzles truck_4_prittles truck_4_skipples truck_4_crottles truck_4_dupples)
))
(assert (>= 8 
(+ truck_5_nuzzles truck_5_prittles truck_5_skipples truck_5_crottles truck_5_dupples)
))
(assert (>= 8 
(+ truck_6_nuzzles truck_6_prittles truck_6_skipples truck_6_crottles truck_6_dupples)
))
(assert (>= 8 
(+ truck_7_nuzzles truck_7_prittles truck_7_skipples truck_7_crottles truck_7_dupples)
))
(assert (>= 8 
(+ truck_8_nuzzles truck_8_prittles truck_8_skipples truck_8_crottles truck_8_dupples)
))

; Question 2 part
(assert (or (and (= truck_1_prittles 0) (>= truck_1_crottles 0)) (and (= truck_1_crottles 0) (> truck_1_prittles 0))))
(assert (or (and (= truck_2_prittles 0) (>= truck_2_crottles 0)) (and (= truck_2_crottles 0) (> truck_2_prittles 0))))
(assert (or (and (= truck_3_prittles 0) (>= truck_3_crottles 0)) (and (= truck_3_crottles 0) (> truck_3_prittles 0))))
(assert (or (and (= truck_4_prittles 0) (>= truck_4_crottles 0)) (and (= truck_4_crottles 0) (> truck_4_prittles 0))))
(assert (or (and (= truck_5_prittles 0) (>= truck_5_crottles 0)) (and (= truck_5_crottles 0) (> truck_5_prittles 0))))
(assert (or (and (= truck_6_prittles 0) (>= truck_6_crottles 0)) (and (= truck_6_crottles 0) (> truck_6_prittles 0))))
(assert (or (and (= truck_7_prittles 0) (>= truck_7_crottles 0)) (and (= truck_7_crottles 0) (> truck_7_prittles 0))))
(assert (or (and (= truck_8_prittles 0) (>= truck_8_crottles 0)) (and (= truck_8_crottles 0) (> truck_8_prittles 0))))

(maximize number_prittles)
(check-sat)
(get-model)






















~~~
