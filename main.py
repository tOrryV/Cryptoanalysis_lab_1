import csv


def read_csv(file_path, read_type='int', delimiter=',', encoding='utf-8'):
    """
    Universal function for reading CSV files.

    :param file_path: Path to the CSV file (string).
    :param delimiter: Column delimiter used in the file (default: ',').
    :param encoding: Encoding of the CSV file (default: 'utf-8').
    :param read_type: Desired type for values:
                 - 'int'   -> convert values to integers
                 - 'float' -> convert values to floating-point numbers
                 (default: 'int'.)
    :return: List of rows, where each row is represented as a list of numeric values
             (int or float) in the same order as they appear in the file.
    """

    with open(file_path, mode='r', encoding=encoding, newline='') as f:
        reader = csv.reader(f, delimiter=delimiter)

        if read_type == 'int':
            return [list(map(int, row)) for row in reader]
        elif read_type == 'float':
            return [list(map(float, row)) for row in reader]
        else:
            return list(reader)


#------------------------------ CALCULATION PROBABILITIES ------------------------------#
def calc_ct_prob(prob_pt, prob_keys, cipher_table, n=20):
    """
    Function for calculating the probability distribution of ciphertexts
    based on given plaintext and key probability distributions.

    :param prob_pt: List of probabilities for each plaintext.
    :param prob_keys: List of probabilities for each key.
    :param cipher_table: Encryption table mapping [key][plaintext] -> ciphertext.
    :param n: Length of prob_pt, i.e., the number of possible plaintexts.
    :return: List of ciphertext probabilities, where each index corresponds
             to the probability of a specific ciphertext.
    """

    prob_ct = [0 for _ in range(n)]

    for msg in range(n):
        for key in range(n):
            ct = cipher_table[key][msg]
            prob_ct[ct] += prob_keys[key] * prob_pt[msg]

    return prob_ct


def calc_pt_ct_prob(prob_pt, prob_keys, cipher_table, n=20):
    """
    Function for calculating the joint probability distribution of plaintext–ciphertext pairs
    based on given plaintext and key probability distributions.

    :param prob_pt: List of probabilities for each plaintext.
    :param prob_keys: List of probabilities for each key.
    :param cipher_table: Encryption table mapping [key][plaintext] -> ciphertext.
    :param n: Length of prob_pt, i.e., the number of possible plaintexts.
    :return: 2D list (matrix) of size n x n, where each entry [msg][ct] represents
             the probability that plaintext 'msg' is encrypted into ciphertext 'ct'.
    """

    prob = [[0 for _ in range(n)] for _ in range(n)]

    for msg in range(n):
        for key in range(n):
            ct = cipher_table[key][msg]
            prob[msg][ct] += prob_keys[key] * prob_pt[msg]

    return prob


def calc_pt_if_exist_ct_prob(prob_mc, prob_c, n=20):
    """
    Function for calculating the conditional probability distribution P(M | C),
    i.e., the probability of each plaintext given a specific ciphertext.

    :param prob_mc: 2D list (matrix) of joint probabilities P(M, C),
                    where entry [msg][ct] corresponds to the probability of plaintext 'msg'
                    and ciphertext 'ct' occurring together.
    :param prob_c: List of ciphertext probabilities P(C),
                   where each index corresponds to the probability of a specific ciphertext.
    :param n: Length of prob_mc, i.e., the number of len list of probability plaintext-ciphertext.
    :return: 2D list (matrix) of size n x n, where each entry [msg][ct] represents
             the conditional probability P(M | C = ct).
    """

    prob = [[0 for _ in range(n)] for _ in range(n)]

    for msg in range(n):
        for ct in range(n):
            prob[msg][ct] += prob_mc[msg][ct] / prob_c[ct]

    return prob


#------------------------------ CALCULATION DECISION FUNCTIONS ------------------------------#
def calc_deterministic_func(pm_if_c, n=20):
    """
    Function for calculating the deterministic Bayes decision function δ_B(C),
    i.e., for each ciphertext C it selects the plaintext M with the highest
    conditional probability P(M | C).

    :param pm_if_c: 2D list (matrix) of conditional probabilities P(M | C),
                    where entry [msg][ct] corresponds to the probability of plaintext 'msg'
                    given ciphertext 'ct'.
    :param n: Number of possible plaintexts/ciphertexts (matrix dimension).
    :return: List of length n, where each entry [ct] represents the index of the
             most probable plaintext M for the given ciphertext C = ct.
    """

    delta = [0 for _ in range(n)]

    for ct in range(n):
        best_prob = -1.0
        best_msg = 0
        for msg in range(n):
            if pm_if_c[msg][ct] > best_prob:
                best_prob = pm_if_c[msg][ct]
                best_msg = msg
        delta[ct] = best_msg

    return delta


def calc_stochastic_func(pm_if_c, n=20):
    """
    Function for calculating the optimal stochastic Bayes decision function δ_S(C, M),
    i.e., for each ciphertext C it determines the set of plaintexts M that achieve
    the maximum conditional probability P(M | C) and distributes the probability mass
    uniformly among them.

    :param pm_if_c: 2D list (matrix) of conditional probabilities P(M | C),
                    where entry [msg][ct] corresponds to the probability of plaintext 'msg'
                    given ciphertext 'ct'.
    :param n: Number of possible plaintexts/ciphertexts (matrix dimension).
    :return: 2D list (matrix) of size n x n, where each row [ct] represents the
             probability distribution over plaintexts M for the given ciphertext C = ct.
             Each row sums to 1 across the selected argmax messages.
    """

    delta = [[0.0 for _ in range(n)] for _ in range(n)]

    for ct in range(n):
        best_prob = -1.0
        best_msgs = []
        for msg in range(n):
            if pm_if_c[msg][ct] > best_prob:
                best_prob = pm_if_c[msg][ct]
                best_msgs = [msg]
            elif pm_if_c[msg][ct] == best_prob:
                best_msgs.append(msg)

        coef = 1.0 / len(best_msgs)
        for msg in best_msgs:
            delta[ct][msg] = coef

    return delta


#------------------------------ CALCULATION AVERAGE LOSES ------------------------------#
def calc_average_loss_deterministic_func(prob_m_c, delta, n=20):
    """
    Function for calculating the average loss directly for a deterministic decision rule (0–1 loss),
    i.e., computes 1 - sum_c P(M = δ(C=c), C=c), without constructing the loss matrix.

    :param prob_m_c: 2D list (matrix) of joint probabilities P(M, C),
                     where entry [m][c] is the probability of plaintext m and ciphertext c.
    :param delta: List of length n representing the deterministic decision function δ(C),
                  where delta[c] is the index of the chosen plaintext M for ciphertext C.
    :param n: Number of possible plaintexts/ciphertexts (matrix dimension).
    :return: Average loss (float), equal to 1 - sum over c of P(M = delta[c], C = c).
    """
    total = 0.0
    for c in range(n):
        m = delta[c]
        total += prob_m_c[m][c]
    return 1.0 - total


def calc_average_loss_stochastic_func(prob_m_c, delta, n=20):
    """
    Function for calculating the average loss directly for a stochastic decision rule (0–1 loss).
    The average loss is computed as:
        L(δ_S) = 1 - sum_{m,c} P(M=m, C=c) * δ_S(c, m)

    :param prob_m_c: 2D list (matrix) of joint probabilities P(M, C),
                     where entry [m][c] is the probability of plaintext m and ciphertext c.
    :param delta: 2D list (matrix) of size n x n representing the stochastic decision rule δ_S,
                        where row [c] is a probability distribution over plaintexts M
                        (each row sums to 1).
    :param n: Number of possible plaintexts/ciphertexts (matrix dimension).
    :return: Average loss (float), equal to 1 - sum_{m,c} P(M=m, C=c) * δ_S(c, m).
    """
    total = 0.0
    for c in range(n):
        for m in range(n):
            total += prob_m_c[m][c] * delta[c][m]
    return 1.0 - total


#------------------------------ MAIN ------------------------------#
def main():
    """
    Main function for executing cryptanalysis laboratory tasks.
    It loads probability distributions and the cipher table from CSV files,
    computes all required probability matrices, decision functions, and average losses,
    and then executes the operation chosen by the user.

    Workflow:
    1. Reads plaintext and key probability distributions from 'data/prob_10.csv'.
    2. Reads the cipher table from 'data/table_10.csv'.
    3. Computes:
       - P(C): probability distribution of ciphertexts,
       - P(M, C): joint probability distribution of plaintext–ciphertext pairs,
       - P(M | C): conditional probability distribution of plaintext given ciphertext.
    4. Computes optimal decision functions:
       - δ_B(C): deterministic Bayes decision function,
       - δ_S(C, M): stochastic Bayes decision function.
    5. Computes average losses:
       - L(δ_B): average loss for the deterministic decision rule,
       - L(δ_S): average loss for the stochastic decision rule.
    6. Asks the user to choose one of the available operations:
       1. Print probability distribution P(C),
       2. Print joint probability distribution P(M, C),
       3. Print conditional probability distribution P(M | C),
       4. Print optimal deterministic decision function δ_B,
       5. Print optimal stochastic decision function δ_S,
       6. Print average loss for δ_B,
       7. Print average loss for δ_S.
    """

    prob_csv_data = read_csv('data/prob_10.csv', 'float')
    prob_pt, prob_keys = prob_csv_data
    cipher_table_data = read_csv('data/table_10.csv')

    pc = calc_ct_prob(prob_pt, prob_keys, cipher_table_data)
    pmc = calc_pt_ct_prob(prob_pt, prob_keys, cipher_table_data)
    pm_if_c = calc_pt_if_exist_ct_prob(pmc, pc)
    df = calc_deterministic_func(pm_if_c)
    sf = calc_stochastic_func(pm_if_c)
    aldf = calc_average_loss_deterministic_func(pmc, df)
    alsf = calc_average_loss_stochastic_func(pmc, sf)

    choose = int(input(f'Choose the operation:\n1. Probability of cipher text P(C)\n2. Probability of '
                       f'plaintext–ciphertext pairs P(M, C)\n3. Probability of plaintext if ciphertext exist\n'
                       f'4. Optimal deterministic decision function\n5. Optimal stochastic decision function\n'
                       f'6. Average loss for deterministic decision function\n7. Average loss for stochastic '
                       f'decision function\n'))

    match choose:
        case 1:
            pc_formatted = [f'{val:.3f}' for val in pc]
            print(f'Result of calculating cipher text probability P(C):\n{pc_formatted}')
        case 2:
            print(f'Result of calculating plaintext–ciphertext pairs probability P(M, C):')
            for row in pmc:
                print([f'{val:.3f}' for val in row])
        case 3:
            print(f'Result of calculating plaintext if ciphertext exist probability P(M | C):')
            for row in pm_if_c:
                print([f'{val:.3f}' for val in row])
        case 4:
            print(f'Result of calculating optimal deterministic decision function:')
            print(df)
        case 5:
            print(f'Result of calculating optimal stochastic decision function:')
            for row in sf:
                print([f'{val:.1f}' for val in row])
        case 6:
            print(f'Result of calculating average loss for deterministic decision function: {aldf:.4f}')
        case 7:
            print(f'Result of calculating average loss for stochastic decision function: {alsf:.4f}')
        case _:
            print(f'Incorrect value input! Try again')


if __name__ == '__main__':
    main()
