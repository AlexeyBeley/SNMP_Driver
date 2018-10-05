import pdb
import time
import datetime
import _thread
import queue
from enum import Enum
from pysnmp.carrier.asyncore.dispatch import AsyncoreDispatcher
from pysnmp.carrier.asyncore.dgram import udp
from pyasn1.codec.ber import encoder, decoder
from pysnmp.proto import api


class SnmpJob:
    """
    Class for a job towards the device. Indicates a started physical interference
    with a device.
    """

    def __init__(self):
        self.str_address = ""
        self.id = ""
        self.datetime_start = datetime.datetime.now()
        self.reply = None


class SnmpDriver(object):
    def __init__(self, mode, logger, **kwargs):
        self.mode = mode
        self.logger = logger
        self.dict_dispatchers = {}
        self.dict_dispatchers_locks = {}
        lst_dispatcher_keys = []
        if mode == SnmpDriver.OperationMode.MULTI_THREAD:
            if "int_thread_count" not in kwargs:
                raise Exception
            if type(kwargs["int_thread_count"]) != int:
                raise Exception

            self.int_thread_count = kwargs["int_thread_count"]

            lst_dispatcher_keys = range(self.int_thread_count)

        elif mode == SnmpDriver.OperationMode.SINGLE_THREAD:
            lst_dispatcher_keys = ["0"]

        elif mode == SnmpDriver.OperationMode.PER_DEVICE:
            pass
        else:
            raise Exception

        self.pMod = api.protoModules[api.protoVersion2c]
        self.dict_started_jobs = {}
        self.q_jobs_to_start = queue.Queue()
        self.q_msgs_completed = queue.Queue()
        self.bool_alive = False

        self.int_seconds_timeout = 10  # Single job timeout
        self.int_mib_frame_limit = 50  # Maximum count of mibs to be sent at one job
        self.int_job_retries_count = 3  # Number of retries if failed to send a mibs frame

        for str_id in lst_dispatcher_keys:
            self.init_new_dispatcher(str_id)

    def init_new_dispatcher(self, id_src):
        self.dict_dispatchers[id_src] = AsyncoreDispatcher()
        self.dict_dispatchers_locks[id_src] = _thread.allocate_lock()

        self.dict_dispatchers[id_src].registerRecvCbFun(self.cbRecvFun)
        self.dict_dispatchers[id_src].registerTransport(udp.domainName, udp.UdpSocketTransport().openClientMode())
        self.dict_dispatchers[id_src].jobStarted(1)

    def stop(self):
        pdb.set_trace()
        self.bool_alive = False
        time.sleep(0.5)

        try:
            self._clean_dispatcher(self.transport_dispatcher)
        except Exception as inst:
            pass

    def start(self):
        self.bool_alive = True
        for transport_dispatcher in self.dict_dispatchers.values():
            _thread.start_new_thread(transport_dispatcher.runDispatcher, ())
        #self.start_thread()
        _thread.start_new_thread(self.start_thread, ())

    def start_thread(self):
        pdb.set_trace()

        while self.bool_alive:
            bool_sleep = not (self.handle_completed_jobs_routine())

            if bool_sleep:
                time.sleep(0.1)

    def handle_completed_jobs_routine(self):
        """

        :return: bool True if there were jobs handled
        """
        pdb.set_trace()
        bool_ret = False
        while self.q_msgs_completed.qsize() > 0:
            bool_ret = True
            pair_address, b_Msg = self.q_msgs_completed.get()
            if pair_address[0] not in self.dict_started_jobs:
                continue
            while b_Msg:
                rspMsg, b_Msg = decoder.decode(b_Msg, asn1Spec=self.pMod.Message())
                rspPDU = self.pMod.apiMessage.getPDU(rspMsg)
                id_rspPDU = self.pMod.apiPDU.getRequestID(rspPDU)
                # Match response to request
                try:
                    self.lock_started_jobs.acquire()

                    for int_key, job_snmp_started in self.dict_started_jobs[pair_address[0]].items():
                        if self.pMod.apiPDU.getRequestID(job_snmp_started.reqPDU) != id_rspPDU:
                            continue

                        # Check for SNMP errors reported
                        errorStatus = self.pMod.apiPDU.getErrorStatus(rspPDU)
                        if errorStatus:
                            job_snmp_started.reply = "Error:" + str(errorStatus.prettyPrint())
                            str_ret = ""
                            try:
                                lst_ret = []
                                for oid, val in self.pMod.apiPDU.getVarBinds(rspPDU):
                                    lst_ret.append((oid.prettyPrint(), val.prettyPrint()))
                                str_ret = str(lst_ret)
                            except Exception:
                                pass
                            job_snmp_started.reply += str_ret
                        else:
                            lst_ret = []
                            for oid, val in self.pMod.apiPDU.getVarBinds(rspPDU):
                                lst_ret.append((oid.prettyPrint(), val.prettyPrint()))
                            job_snmp_started.reply = lst_ret
                        break

                finally:
                    self.lock_started_jobs.release()
            bool_sleep = False
        return bool_ret

    def execute(self, str_address, lst_mibs):
        """
        Splits the list of mibs to be sent to frames.
        Replies composed and returned to the caller.
        Each frame handled by execute_frame.

        :param str_address: Destination address to send
        :param lst_mibs: List of mibs to be sent
        :return:
        """
        dict_ret = {}

        int_frames_count = int(len(lst_mibs) / self.int_mib_frame_limit)
        if len(lst_mibs) % self.int_mib_frame_limit:
            int_frames_count += 1
        range_count = range(int_frames_count)

        for int_frame_number in range_count:
            # check if there is a reply for the specific frame
            if int_frame_number in list(dict_ret.keys()):
                if dict_ret[int_frame_number] is not None:
                    continue
            _thread.start_new_thread(self.execute_frame,
                                     (str_address,
                                      lst_mibs[int_frame_number * self.int_mib_frame_limit:(int_frame_number + 1) * self.int_mib_frame_limit],
                                      dict_ret, int_frame_number))
        for _ in range(self.int_job_retries_count * self.int_seconds_timeout * 100):
            if len(list(dict_ret.keys())) == int_frames_count:
                break
            time.sleep(0.01)
        else:
            # Continue to retries
            #  todo:
            pass
            #continue

        lst_ret = self.map_replies_to_list(lst_mibs, dict_ret)
        return lst_ret

    def map_replies_to_list(self, lst_mibs, dict_ret):
        lst_ret = []
        for int_frame_number in range(len(lst_mibs)):
            if int_frame_number not in dict_ret:
                # Prepare list of [mib, None] to indicate error
                lst_frame_ret = list(map(lambda x: [x, None],
                                         lst_mibs[int_frame_number * self.int_mib_frame_limit:
                                         (int_frame_number + 1) * self.int_mib_frame_limit]))
            else:
                if dict_ret[int_frame_number] is not None:
                    lst_frame_ret = dict_ret[int_frame_number]
                else:
                    lst_frame_ret = []
            lst_ret += lst_frame_ret
        return lst_ret

    def execute_frame(self, str_address, lst_mibs, dict_ret, int_frame_index):
        """

        :param str_address: string destination address
        :param lst_mibs: Frame to be sent
        :param dict_ret: put the reply here at place int_frame_index
        :param int_frame_index: Index to put the reply at
        :return:
        """
        # Build PDU
        for _ in range(self.int_job_retries_count):

            pdb.set_trace()
            if str_address not in self.dict_started_jobs:
                self.dict_started_jobs[str_address] = {}

        job_new = SnmpJob()
        job_new.str_address = str_address

        job_new.reqPDU = self.pMod.GetRequestPDU()
        self.pMod.apiPDU.setDefaults(job_new.reqPDU)
        lst_reqs = [(x, self.pMod.Null('')) for x in lst_mibs]
        self.pMod.apiPDU.setVarBinds(job_new.reqPDU, lst_reqs)
        job_new.datetime_start = datetime.datetime.now()

        job_new.id = 0

        # Build message
        job_new.reqMsg = self.pMod.Message()

        self.pMod.apiMessage.setDefaults(job_new.reqMsg)
        self.pMod.apiMessage.setCommunity(job_new.reqMsg, 'incap424')
        self.pMod.apiMessage.setPDU(job_new.reqMsg, job_new.reqPDU)

        try:
            self.lock_started_jobs.acquire()
            while job_new.id in self.dict_started_jobs[str_address]:
                job_new.id += 1

            transportDispatcher.sendMessage(encoder.encode(job_snmp.reqMsg), udp.domainName,
                                                (job_snmp.str_address, 161))

            self.dict_started_jobs[str_address][job_new.id] = job_new
        finally:
            self.lock_started_jobs.release()

        self.q_jobs_to_start.put(job_new)
        for i in range(self.int_seconds_timeout * 100):
            if job_new.reply:
                break
            time.sleep(0.01)

        try:
            self.lock_started_jobs.acquire()
            del self.dict_started_jobs[str_address][job_new.id]
        finally:
            self.lock_started_jobs.release()

        dict_ret[int_frame_index] = job_new.reply
        return job_new.reply

    def cbRecvFun(self, transportDispatcher, transportDomain, transportAddress,
                  wholeMsg):
        # print("complete:"+str(wholeMsg))
        self.q_msgs_completed.put([transportAddress, wholeMsg])
        # print(transportDispatcher)
        return

    def _clean_dispatcher(self, transportDispatcher):
        transportDispatcher.jobFinished(1)
        time.sleep(2)

        try:
            transportDispatcher.closeDispatcher()
        except Exception as inst:
            pass

        # closeTransport
        try:
            tpt = transportDispatcher.getTransport(udp.domainName)
        except Exception as inst:
            pass

        # pdb.set_trace()
        try:
            tpt.del_channel()
        except Exception as inst:
            pass
        try:
            tpt.closeTransport()
        except Exception as inst:
            pass
        try:
            tpt.close()
        except Exception as inst:
            pass
        try:
            transportDispatcher.unregisterRecvCbFun()
        except Exception as inst:
            pass
        try:
            transportDispatcher.unregisterRoutingCbFun()
        except Exception as inst:
            pdb.set_trace()
            pass
        try:
            transportDispatcher.unregisterTimerCbFun()
        except Exception as inst:
            pass
        try:
            transportDispatcher.unregisterTransport(udp.domainName)
        except Exception as inst:
            pass

    class OperationMode(Enum):
        SINGLE_THREAD = 0
        MULTI_THREAD = 1
        PER_DEVICE = 2
