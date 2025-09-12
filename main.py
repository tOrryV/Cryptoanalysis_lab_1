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


def main():
    """
    Main function... tbc

    """

    prob_csv_data = read_csv('data/prob_10.csv', 'float')
    prob_pt, prob_keys = prob_csv_data
    cipher_table_data = read_csv('data/table_10.csv')

    choose = int(input(f'Choose the operation:\n1. Probability of cipher text P(C)\n2. Probability of '
                       f'plaintext–ciphertext pairs P(M, C)\n3. Probability of plaintext if ciphertext exist\n'))

    match choose:
        case 1:
            pc = calc_ct_prob(prob_pt, prob_keys, cipher_table_data)
            pc_formatted = [f'{val:.3f}' for val in pc]
            print(f'Result of calculating cipher text probability P(C):\n{pc_formatted}')
        case 2:
            pmc = calc_pt_ct_prob(prob_pt, prob_keys, cipher_table_data)
            print(f'Result of calculating plaintext–ciphertext pairs probability P(M, C):\n')
            for row in pmc:
                print([f'{val:.3f}' for val in row])
        case 3:
            pc = calc_ct_prob(prob_pt, prob_keys, cipher_table_data)
            pmc = calc_pt_ct_prob(prob_pt, prob_keys, cipher_table_data)
            pm_if_c = calc_pt_if_exist_ct_prob(pmc, pc)
            print(f'Result of calculating plaintext if ciphertext exist probability P(M | C):\n')
            for row in pm_if_c:
                print([f'{val:.3f}' for val in row])
        case _:
            print(f'Incorrect value input! Try again')


if __name__ == '__main__':
    main()
