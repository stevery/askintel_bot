import re
import os
import sys
import platform as pf
import logging
import pprint
import math
import hashlib
from time import sleep
from datetime import datetime

import soldier

import telegram
from telegram.ext import Updater
from telegram.ext import CommandHandler
from telegram.ext import MessageHandler, Filters

import lib.easyintelligence as easyintelligence
import lib.pnmap as pnmap
import lib.file_processor as fp

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

lib_path = seperator.join(dir_path.split(seperator)[:-3])
sys.path.append(lib_path)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)


ei = easyintelligence.EasyIntell()
MAXLEN = 10


def start(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text="I'm a bot for asking security intelligence, please ask to me!")


def help(bot, update):
    bot.send_message(chat_id=update.message.chat_id,
                     text='''/start, start command describes this bot
/ask (ip|domain|hash), ask command fetches cti from vt, xfe, shodan, and etc
/scan ip (port|port-port)
/help, help''')

def echo(bot, update):
    bot.send_message(chat_id=update.message.chat_id, text=update.message.text)

# todos
# hash
# md5: [a-fA-F\d]30
# sha-1: [a-fA-F\d]40
# sha-256: [a-fA-F\d]64
# domain, url
# todos
# too many if statements, need to be functionize


def message_cleaner(bot, update, args):
    try:
        # for ip quality score
        if "request_id" in args:
            messages = pprint.pformat(args, indent=4)
            bot.send_message(chat_id=update.message.chat_id, text=messages)
        elif args is not None and type(args) is dict:
            messages = pprint.pformat(args, indent=4)
            for arg in args:
                try:
                    message = pprint.pformat(args[arg], indent=4)
                    bot.send_message(chat_id=update.message.chat_id, text="- {}: ".format(arg))
                    if type(args[arg]) is list:
                        for i in args[arg][:MAXLEN]:
                            bot.send_message(chat_id=update.message.chat_id, text=pprint.pformat(i, indent=4))
                    #elif type(args[arg]) is dict:
                    #    for i in sorted(args[arg].items())[:MAXLEN]:
                    #        bot.send_message(chat_id=update.message.chat_id, text=pprint.pformat(i, indent=4))
                    else:
                        bot.send_message(chat_id=update.message.chat_id, text=pprint.pformat(args[arg], indent=4))
                    sleep(2)
                    
                except Exception as e:
                    bot.send_message(chat_id=update.message.chat_id, text="[Error] from message cleaner inside with {}".format(e))
                    pass
        elif args is not None and type(args) is str:
            bot.send_message(chat_id=update.message.chat_id, text=args)
        else:
            bot.send_message(chat_id=update.message.chat_id, text='Return value is none')

    except Exception as e:
        bot.send_message(chat_id=update.message.chat_id, text="[Error] from message cleaner with {}".format(e))
        pass


def scan(bot, update, args):
    if len(args) != 2:
        bot.send_message(chat_id=update.message.chat_id, text="Wrong input")
    else:
        ip = args[0].strip()
        port = args[1].strip()
        start_time = datetime.now()
        result = pnmap.simple_scan(ip,port)
        finish_time = datetime.now()
        bot.send_message(chat_id=update.message.chat_id, text="scan will takes over 2 min")
        if result == False:
            bot.send_message(chat_id=update.message.chat_id, text="ip or port is invalid")
        else:
            bot.send_message(chat_id=update.message.chat_id, text="Scan start time: {:%Y-%m-%d %H:%M:%S}".format(start_time))
            bot.send_message(chat_id=update.message.chat_id, text="Scan finish time: {:%Y-%m-%d %H:%M:%S}".format(finish_time))
            bot.send_message(chat_id=update.message.chat_id, text=result)
        print(result)
        

def asks(bot, update, args):
    args = args[0].strip()
    result = ""
    ip_search = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    md5_search = re.compile(r'^[a-fA-F\d]{32}$')
    sha1_search = re.compile(r'^[a-fA-F\d]{40}$')
    sha256_search = re.compile(r'^[a-fA-F\d]{64}$')
    domain_search = re.compile(r'((http|https)\:\/\/)?[a-zA-Z0-9\.\/\?\:@\-_=#]+\.([a-zA-Z]){2,6}([a-zA-Z0-9\.\&\/\?\:@\-_=#])*')
    if ip_search.search(args):
        ei.ask_ip(args, itype='ip')
        bot.send_message(chat_id=update.message.chat_id, text="You asked for ip address: {}".format(args))
        bot.send_message(chat_id=update.message.chat_id, text="https://www.virustotal.com/#/ip-address/{}".format(args))
        message_cleaner(bot, update, ei.result['virustotal'])
        sleep(2)

        bot.send_message(chat_id=update.message.chat_id, text='https://www.shodan.io/search?query={}'.format(args))
        message_cleaner(bot, update, ei.result['shodan'])
        sleep(2)

        bot.send_message(chat_id=update.message.chat_id, text='https://exchange.xforce.ibmcloud.com/ip/{}'.format(args))
        message_cleaner(bot, update, ei.result['xfe'])
        sleep(2)

        bot.send_message(chat_id=update.message.chat_id, text='https://www.ipqualityscore.com/free-ip-lookup-proxy-vpn-test/lookup/{}'.format(args))
        message_cleaner(bot, update, ei.result['ipqs'])
        sleep(2)


    elif md5_search.search(args) or sha1_search.search(args) or sha256_search.search(args):
        ei.ask_hash(args, itype='hash')
        bot.send_message(chat_id=update.message.chat_id, text='You asked hash value for: {}'.format(args))
        message_cleaner(bot, update, "Virustotal Result")
        message_cleaner(bot, update, ei.result['virustotal'])
        message_cleaner(bot, update, "XFE Result")
        message_cleaner(bot, update, ei.result['xfe'])

    elif domain_search.search(args):
        ei.ask_domain(args, itype='domain')
        bot.send_message(chat_id=update.message.chat_id, text='You asked domain value for: {}'.format(args))
        message_cleaner(bot, update, "Virustotal Domain Result")
        message_cleaner(bot, update, ei.result['virustotal'])
        
        ei.ask_url(args, itype='url')
        bot.send_message(chat_id=update.message.chat_id, text='You asked url value for: {}'.format(args))
        message_cleaner(bot, update, "Virustotal URL Result")
        message_cleaner(bot, update, ei.result['virustotal'])
        message_cleaner(bot, update, "XFE URL Result")
        message_cleaner(bot, update, ei.result['xfe'])
        
    else:
        result = "You asked wrong queries. {}".format(args)
        bot.send_message(chat_id=update.message.chat_id, text=result)


def file_catcher(bot, update):
    doc = update.message.document
    file_id = telegram.File(doc.file_id)["file_id"]
    file_name = telegram.File(doc.file_name)["file_id"]
    tmp_path = "tmp{}{}".format(seperator,file_name)

    newFile = bot.getFile(file_id)
    newFile.download(tmp_path)
    file_md5 = hashlib.md5(fp.file_as_bytes(open("tmp{}{}".format(seperator,file_name), 'rb'))).hexdigest()
    bot.send_message(chat_id=update.message.chat_id, text="You uploaded {}, md5({}), telegram_message_id({})".format(file_name, file_md5, update.message.message_id))
    fpfp= fp.FileProcessor()
    fpfp.file_checker(tmp_path)
    if fpfp.counter != 0:
        bot.send_message(chat_id=update.message.chat_id, text="You already submtted this sample")
    # virustotal info
    bot.send_message(chat_id=update.message.chat_id, text="virustotal link {}".format(fpfp.vt_url))
    
    # hybrid analysis info
    bot.send_message(chat_id=update.message.chat_id, text="hybrid-analysis link {}".format(fpfp.hybrid_url))




def error(bot, update, error):
    """Log Errors caused by Updates."""
    logger.warning('Update "%s" caused error "%s"', update, error)
    bot.send_message(chat_id=update.message.chat_id, text=logger.warning('Update "%s" caused error "%s"', update, error))


def init_folders():
    soldier.run("mkdir samples")
    soldier.run("mkdir tmp")

def main():
    init_folders()
    updater = Updater(token=ei.teletoken.strip())
    dispatcher = updater.dispatcher

    # command for start
    start_handler = CommandHandler('start', start)
    dispatcher.add_handler(start_handler)

    # command for help
    help_handler = CommandHandler('help', help)
    dispatcher.add_handler(help_handler)

    # command for shell
    echo_handler = MessageHandler(Filters.text, echo)
    dispatcher.add_handler(echo_handler)

    # file processor
    file_handler = MessageHandler(Filters.document, file_catcher)
    dispatcher.add_handler(file_handler)

    # command for ask
    ask_handler = CommandHandler('ask', asks, pass_args=True)
    dispatcher.add_handler(ask_handler)

    # command for network scan
    scan_handler = CommandHandler('scan', scan, pass_args=True)
    dispatcher.add_handler(scan_handler)

    # log all errors
    dispatcher.add_error_handler(error)

    # start bot
    updater.start_polling()


if __name__ == "__main__":
    main()