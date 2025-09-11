import csv


def read_csv(file_path, delimiter=',', encoding='utf-8'):
    """
    Universal function for reading CSV files.

    :param file_path: Path to the CSV file (string).
    :param delimiter: Column delimiter used in the file (default: ",").
    :param encoding: Encoding of the CSV file (default: "utf-8").
    :return: List of rows, where each row is represented as a list of string values
            in the same order as they appear in the file.
    """

    with open(file_path, mode="r", encoding=encoding, newline="") as f:
        reader = csv.reader(f, delimiter=delimiter)
        return list(reader)


def main():
    """
    Main function... tbc

    """

    prob_csv_data = read_csv('data/prob_10.csv')
    prob_ot, prob_keys = prob_csv_data

    cypher_table_data = read_csv('data/table_10.csv')


if __name__ == '__main__':
    main()
