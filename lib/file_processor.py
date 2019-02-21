import os
import sys
import sqlite3
from sqlite3 import Error
import hashlib
import platform as pf
import re
from datetime import datetime

import soldier
import lib.easyintelligence as easyintelligence


mypf = pf.platform()
dir_path = os.path.dirname(os.path.abspath(__file__))
seperator = ""
if re.search(r'^windows', mypf, re.I):
    seperator = "\\"
elif re.search(r'^(linux|Darwin)', mypf, re.I):
    seperator = "/"
else:
    print("Not supported platform")
    print("your os is: {}".format(mypf))
    sys.exit(0)


class DBProcessor:
    def __init__(self):
        self.database = "samples.db"
        #self.conn = sqlite3.connect(self.database)    
        self.rows = []
        self.sql_create_samples_table = """CREATE TABLE IF NOT EXISTS samples (
                                            name text NOT NULL,
                                            counter integer NOT NULL,
                                            md5 text NOT NULL PRIMARY KEY,
                                            sha1 text NOT NULL,
                                            sha256 text NOT NULL,
                                            virustotal text NOT NULL,
                                            hybridanalysis text NOT NULL,
                                            submit_date DATE NOT NULL
                                        );"""
    
        # create a database connection
        self.conn = self.create_connection(self.database)
        if self.conn is not None:
            # create projects table
            self.create_table(self.sql_create_samples_table)
        else:
            print("Error! cannot create the database connection.")


    def create_connection(self, db_file):
        """ create a database connection to the SQLite database
            specified by db_file
        :param db_file: database file
        :return: Connection object or None
        """
        try:
            conn = sqlite3.connect(db_file)
            return conn
        except Error as e:
            print(e)
    
        return None


    def create_table(self, create_table_sql):
        """ create a table from the create_table_sql statement
        :param conn: Connection object
        :param create_table_sql: a CREATE TABLE statement
        :return:
        """
        try:
            c = self.conn.cursor()
            c.execute(create_table_sql)
        except Error as e:
            print(e)


    def select_samples_by_md5(self, md5):
        """
        Query tasks by priority
        :param conn: the Connection object
        :param priority:
        :return:
        """
        cur = self.conn.cursor()
        cur.execute("SELECT * FROM samples WHERE md5=?", (md5,))
    
        self.rows = cur.fetchall()

    def insert_samples(self, sample_info):
        """
        Create a new task
        :param conn:
        :param task:
        :return:
        """
    
        sql = ''' INSERT INTO samples(name,counter,md5,sha1,sha256,virustotal,hybridanalysis,submit_date)
                VALUES(?,?,?,?,?,?,?,?) '''
        cur = self.conn.cursor()
        cur.execute(sql, sample_info)
        return cur.lastrowid

    def update_samples(self, sample_info):
        """
        update priority, begin_date, and end date of a task
        :param conn:
        :param task:
        :return: project id
        """
        sql = ''' UPDATE samples
                SET counter = ? 
                WHERE md5 = ?'''
        cur = self.conn.cursor()
        cur.execute(sql, sample_info)
    

class FileProcessor:
    def __init__(self):
        self.file_path = "sample"
        self.file_name = ""
        self.file_md5 = ""
        self.file_sha1 = ""
        self.file_sha256 = ""
        self.file_date = ""
        self.vt_url = ""
        self.hybrid_url = ""
        self.ei = easyintelligence.EasyIntell()


    def md5_query(self, md5):
        conn = sqlite3.connect('samples.db')


    def file_checker(self, path):
        #binary = file_as_bytes(open("..{}tmp{}{}".format(seperator,seperator, path), 'rb'))

        #binary = file_as_bytes(open(path, 'rb'))   
        self.file_name = path.split(seperator)[-1]
        self.sample = {"binary":file_as_bytes(open(path, 'rb')),
            "name":self.file_name}
        self.file_md5 = hashlib.md5(self.sample["binary"]).hexdigest()
        self.file_sha1 = hashlib.sha1(self.sample["binary"]).hexdigest()
        self.file_sha256 = hashlib.sha256(self.sample["binary"]).hexdigest()
        self.file_date = datetime.now()

        self.counter = 0 
        dp = DBProcessor()
        dp.select_samples_by_md5(self.file_md5)
            #self.dp.select_samples_by_md5(self.file_md5)

        if len(dp.rows) == 0:
            #self.ei.ask_bin({'file': ('sample', binary)})
            self.ei.ask_bin(self.sample)
            try:
                self.vt_url = self.ei.result["virustotal"]["permalink"]
                self.hybrid_url = "https://www.hybrid-analysis.com/sample/{}?environmentId=120".format(self.ei.result["hybrid"]["sha256"])
            except:
                pass
            print(self.vt_url)
            print(self.hybrid_url)
            sample_info = (self.file_name,
                           self.counter,
                           self.file_md5,
                           self.file_sha1,
                           self.file_sha256,
                           self.vt_url,
                           self.hybrid_url,
                           self.file_date)

            print(sample_info)
            with dp.conn:
                dp.insert_samples(sample_info)
            soldier.run('cp tmp{}{} samples{}{}'.format(seperator,self.file_name,seperator,self.file_name))
        else:
            self.counter = dp.rows[0][1] + 1
            sample_info = (self.counter, self.file_md5)
            print(self.counter)
            with dp.conn:
                dp.update_samples(sample_info)

            self.vt_url = dp.rows[0][5]
            self.hybrid_url = dp.rows[0][6]
        soldier.run('rm tmp{}{}'.format(seperator,self.file_name))


        """curl --request GET \
        --url 'https://www.virustotal.com/vtapi/v2/file/report?apikey=01ce6059fc6b30c8a999648cc664baac122761517d310ab1a8865dcd5e244332&resource=67c326feeb47e17a48aae78fe367b8db'
        {"response_code": 0, "resource": "67c326feeb47e17a48aae78fe367b8db", "verbose_msg": "The requested resource is not among the finished, queued or pending scans"}
        """
        print(self.file_md5)


    def file_save(self):
        self.file_name = ""
        self.file_hash = ""


    def file_delete(self):
        pass

    
    def ask_vt(self):
        pass

    
    def ask_hb(self):
        pass


def file_as_bytes(file):
    with file:
        return file.read()


def main():
    fp = FileProcessor()
    fp.file_checker("PLAYER.EXE")



if __name__ == "__main__":
    main()