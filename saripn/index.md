# Structure and randomness in prime numbers


These are notes I took while listening to Terence Tao's lecture on YouTube titled [Structure and randomness in prime numbers](https://www.youtube.com/watch?v=PtsrAw1LR3E&list=PL40B6CDE3FF8C3904&index=5). Most of the topics were taken and paraphrased from his slides, but I added some of his additional comments he made during the lecture. 

There are many other sources where these topics are treated more clearly; however, this post is intended to help me memorize the material. I'm very excited by the fact that these materials are freely available on the web, and I believe they are one of the main reasons why the internet should exist.

## Fundamental theorem of arithmetic

Euclide 300 B.C. - Every natural number larger than 1 can be expressed as a product of one or more primes. This product is unique up to rearrangement.

## Euclid's theorem

Euclide 300 B.C. - There are infinitely many prime numbers

### Reductio ad absurdum proof

- Suppose, for sake of contradiction, that there were only finitely many prime numbers $$p_1, \dots, p_n$$ (e.g. $$2, 3, 5$$);
- Multiply all the primes togheter and add or subtract $$1$$: $$p = p_1 p_2 \pm 1$$ (e.g. $$p = 2*3*5 \pm 1 = 29$$ or $$30$$);
- Then, $$p$$ is a natural number larger than $$1$$ but it is not divisible by one of the prime numbers;
- This contradicts the Fundamental theorem of arithmetics. Hence, there are infinitely many primes.

The larger explicitely known prime is: $$2^{32'582'657} - 1$$.

## Twin primes

Pair $$(p, p + 2)$$ which are both primes.

### Twin prime conjecture

The twin prime conjecture is yet unsolved and states that there are infinitely many pairs of twin primes.



$$\rightarrow$$ **The basic difficulty is that we don't understand how sequence of primes behave**. For example, we have an exact formula for the $$n^{th}$$ square, that is $$n^2$$, but we don't have it for the $$n^{th}$$ prime $$p_n$$ (it seems it behaves randomly).


Despite we don't have an exact formula for the sequence of primes, we have a fairly geed inexact formula:

#### Prime number theorem (Hadamard and de la Vallée-Poussin, 1986)

$$p_n \sim n \ln n$$.
More precisely:
$$\lim_{n \rightarrow \infty} \dfrac{p_n}{n \ln n} = 1$$

This is the best achievement in number theory.

Very informal sketch of proof:
- Create a sound wave (more precisely a  von Mangoldt function) which is noisy at prime number times, and quite other times:

    **von Mangoldt function**
    $$\Lambda(n) = \begin{cases} \log p \text{ if } n = p^k \text{ for some prime } p \text{ and integer } k \geq 1,\\ 0 \text{ otherwise} \end{cases}$$

    $$.**.*.*...*.*...*.*...*.....*$$

- "Listen" (take the Fourier transform) of this wave and record the notes that you hear (the zeroes of the Riemann zeta function). Each note corresponds to a hidden pattern in the distribution of primes.
- Show that certain number of notes do not appear in this music.
- From this and other tools such Fourier analysis one can prove the Prime number theorem.

The techniques to prove prime number theorem can be used to prove many other facts e.g.:
- All large primes have a last digit of $$1,3,7,9$$ with a $$25%$$ proportion of primes having each of these digits (Dirichlet, 1837). Similarly, for other bases than $$10$$;
- All large odd numbers can be expressed as the sum of three primes (Vinogradov, 1937).

## Riemann hypothesis (1859)

The infamous Riemann hypothesis predicts a more precise formula for the $$p_n$$, which should be accurate to an error of about $$\sqrt{n}$$:

$$\int_{2}^{p_n} \dfrac{dt}{\ln t} = n + O(\sqrt{n \ln^3 n})$$

Interestingly, the error $$O(\sqrt{n \ln^3 n})$$ predicted by the Riemann hypothesis is essentially the same type of error one would have expected if the primes were distributed randomly.
Thus, the Riemann hy. asserts (in some sense) that primes are pseudorandom - they behave randomly, even though they actually are deterministic.

## Diffie-Hellman Key Exchange (1976)

Diffie-Hellman key exchange is a secure way to allow two strangers (Alice and Bob) to share a secret, even where their communication is completely open to eavesdroppers.

### Idea

1. Alice locks the secret she wants to send to Bob using her private key;
2. When Bob receives it, he double locks it using his private key, and sends it back to Alice;
3. Alice decrypts the message using her private key and sends it to Bob: now it is only encrypted with Bob's key;
4. Finally, Bob decrypts the secret using his private key.

### Oversimplified DH protocol to send a secret number $$g$$

- Alice and Bob agree (over an insicure network) on a large prime $$p$$;
- Alice picks a key $$a$$, "locks" $$g$$ by computing $$g^a \mod p$$, and sends it to Bob;
- Bob picks a key $$b$$, "double locks" $$g^a \mod p$$ by computing $$(g^a)^b=g^{ab} \mod p$$ and sends it back to Alice;
- Alice takes the $$a^{th}$$ root of $$g^{ab}$$ to create $$g^b mod p$$ to send back to Bob;
- Finally Bob does the $$b^{th}$$ root and decrypts the message.

It's not known whether this algorithm is truly secure (issure related to P $$\ne$$ NP problem).

The true protocol works slightly differently, generating the shared secret only after the exchange (and not as initially mentioned as $$g$$).

This shared secred can then be used to communicate with each other with a standard chiper (ex. AES).

## Sieve Theory

The prime numbers are not completely random in their behaviour - they do obey some obvious patterns e.i. they are all odd (with one exception); they are all adjacent to a multiple of six (with two exceptions).

Sieve theory is an efficient way to capture these structures in the primes, and is one of our fundamental tools for understanding the primes.

Sieve study the set of primes in aggragate manner, rather than trying to focus on each prime individually.

Classic example of Sieve is the **Sieve of Eratosthenes** which let one capture all the primes bewtween $$\sqrt{N}$$ and $$N$$, for any given $$N$$ as follows:

- Start with all integers between $$\sqrt{N}$$ and $$N$$;
- Throw out all multiples of $$2$$;
- Throw out all multiple of $$3$$;
- $$\dots$$
- After throwing out all multiples of any prime less than $$\sqrt{N}$$, the remaining set forms the primes from $$\sqrt{N}$$ to $$N$$.

In the literature there are more advanced sieves.

## Green-Tao Theorem (2004)

The primes contain arbitrarly long arithmetic progressions.

**Arithmetic progression**: $$a, a+r, \dots, a + (k-1) r$$

In particular, for any given $$k$$, the primes contain infinitely many arithmetic progessions of length $$k$$.

The longest explicitely known arithmetic progession of primes contain $$23$$ primes (discovered by Frind, Jobling and Underwood in 2004).

$$2$$

$$3,5,7$$

$$5, 11, 17, 23$$

$$5, 11, 17, 23, 29$$

$$7, 37, 67, 97, 127, 157$$

$$7, 157, 307, 457, 607, 757$$

$$\dots$$

There's still so much work to be done. For instance, the theorem shows that the first arithmetic progression of length $$k$$ has all entries less than $$2^{2^{2^{2^{2^{2^{2^{100^k}}}}}}}$$, but the true size is conjectured to be more like $$k^k$$.

