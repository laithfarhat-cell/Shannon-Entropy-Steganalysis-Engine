# What the measurements mean

## Byte entropy is a property of a histogram

For a uniformly selected byte position in an observed region of length $N$, the empirical mass at value $i$ is $p_i=n_i/N$. Its self-information is $-\log_2 p_i$ bits. Averaging over observed values gives

$$H=-\sum_{i:n_i>0} p_i\log_2 p_i.$$

One occupied bin gives exactly zero; 256 equally frequent values give exactly eight bits/byte. We report zero by convention for empty input, but `null` for the entropy of a section with no file-backed bytes. This is a plug-in estimate, not a source entropy rate. With $N<256$ its upper bound is $\log_2 N$. The estimate is downward biased for small samples, and permuting bytes does not change it. Even `00 01 ... FF` repeated indefinitely scores 8.

Machine code often has biased opcode, alignment and immediate bytes. Compression removes redundancy; effective encryption also tends to produce a flat histogram. A sliding profile localizes transitions lost in a global average. A window of $W$ bytes at stride $S$ trades spatial resolution for variance; overlapping samples are correlated. The last full window is aligned to EOF to avoid dropping a suffix. A short file yields one short window; an empty file yields none. Strides larger than the window leave gaps. Histogram work is $O(N + K W)$ for $K$ windows; the implementation enforces a work budget.

### Two additional diagnostics, not an encryption classifier

Under independent uniform bytes, $E_i=N/256$ and Pearson's statistic is

$$X^2=\sum_{i=0}^{255}\frac{(n_i-E_i)^2}{E_i}.$$

There are 255 independent bin counts once their sum is fixed. A small upper-tail probability under $\chi^2_{255}$ argues **against** uniformity. The CLI omits this asymptotic p-value when $E_i<5$. Large p-values do not establish unpredictability or independence.

The π diagnostic takes adjacent six-byte groups, treats each half as an unsigned big-endian coordinate divided by $2^{24}$, and estimates $4\Pr(x^2+y^2\le1)$. Under independent uniform coordinates the expected hit fraction approximates the area of a quarter unit disk, $\pi/4$. For $m$ independent points, the estimate's standard error is approximately $4\sqrt{(\pi/4)(1-\pi/4)/m}$. Incomplete trailing groups are discarded. Failure may indicate structure or sample variation; neither this estimate nor Pearson's test reliably distinguishes ciphertext from compressed data. Format signatures, provenance and corroborating evidence matter more than either number alone.

## Pair-of-values steganalysis

Replacing bit zero leaves the other seven bits unchanged. In channel $c$, sample values $2k$ and $2k+1$ therefore form a closed pair. Write $a_k,b_k$ for their counts and $t_k=a_k+b_k$. Under replacement by independent fair bits, conditional on $t_k$, $a_k\sim\mathrm{Binomial}(t_k,1/2)$. Both expected cell counts are $e_k=t_k/2$. If a fraction $q$ is replaced uniformly, the expected original imbalance is scaled by $1-q$; weak replacement can be hard to detect.

**Classical Westfeld–Pfitzmann curve.** For $m$ retained pairs, use the single-sided pair score and conventional reference distribution:

$$X^2_{WP}=\sum_k\frac{(a_k-e_k)^2}{e_k}=\tfrac12\sum_k\frac{(a_k-b_k)^2}{t_k},\qquad s_{WP}=\Pr(\chi^2_{m-1}\ge X^2_{WP}).$$

The curve historically called “embedding probability” is a **compatibility score**, not $P(\mathrm{stego}\mid\mathrm{pixels})$. In particular the classical statistic is not a calibrated conditional Pearson statistic. Under the independent fair-bit model, including **both** cells instead yields

$$X^2_{cond}=\sum_k\frac{(a_k-b_k)^2}{t_k}=2X^2_{WP}.$$

Each retained pair contributes one free split, so the large-sample reference here is $\chi^2_m$. JSON reports both upper tails. We omit pairs with $t_k<10$, and return `null` if fewer than two pairs qualify. Natural pixels rarely satisfy the independence model.

**Localization.** Accumulate one histogram per channel through 10%, 20%, …, 100% of rows, rounding up and collapsing duplicate endpoints. Each scan also reports binary entropy of parity in the newly added row band, using the same Shannon formula on the two parity counts (range 0–1 bit). LSB maps visualize decoded intensity bit zero, not alpha, palette indices, or original compressed bytes.

**Decision rule.** At least 16 populated pairs, $s_{WP}\ge0.95$, and conditional upper tail $\ge0.05$ qualify a channel. Two of three channels must qualify for three consecutive cumulative scans. The rule can retain evidence of a prefix even if later cover rows dilute it. These overlapping scans are not independent confirmations; a threshold is an operational heuristic, not a chosen false-positive rate. Grayscale and palette expansion do not provide three original RGB channels, so the color verdict is disabled there.

A noisy photo, dither, or generated texture can pass without embedding. Small payloads, biased bits, and methods other than LSB replacement can evade this test. Flat and tiny images may have insufficient eligible pairs. A labeled, representative held-out corpus is required to estimate real-world sensitivity and false-positive rates. The deterministic lab demonstrates behavior under controlled assumptions only.

## References

- C. E. Shannon, *A Mathematical Theory of Communication*, Bell System Technical Journal (1948).
- A. Westfeld and A. Pfitzmann, *Attacks on Steganographic Systems*, Information Hiding, LNCS 1768, pp. 61–76 (2000), DOI: 10.1007/10719724_5.
