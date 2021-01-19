// Copyright (c) 2015-2021, NVIDIA CORPORATION.
// SPDX-License-Identifier: Apache-2.0

#include <inttypes.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <proxyfs.h>
#include <fcntl.h>

#include <ioworker.h>
#include <proxyfs_jsonrpc.h>
#include <json_utils.h>
#include <debug.h>
#include <time_utils.h>
#include <time.h>
#include <socket.h>
#include <fault_inj.h>

#define MIN(a,b) (((a)<(b))?(a):(b))

// If set, uses "fast" rpc port for reads and writes
bool use_fastpath_for_read  = true;
bool use_fastpath_for_write = true;

typedef struct {
    uint64_t   op_type;
    uint8_t    mount_id[MOUNT_ID_SIZE];
    uint64_t   inode_number;
    uint64_t   offset;
    uint64_t   length;
} io_req_hdr_t;

typedef struct {
    uint64_t   error;
    uint64_t   io_size;
} io_resp_hdr_t;

void proxyfs_set_rw_fastpath()
{
    use_fastpath_for_read  = true;
    use_fastpath_for_write = true;
}

void proxyfs_unset_rw_fastpath()
{
    use_fastpath_for_read  = false;
    use_fastpath_for_write = false;
}

uint64_t endOfRequest = 0x9988776655443322;

typedef enum {
    VOL_NAME = 0,
    MOUNT_OPTS,
    AUTH_USER_ID,
    AUTH_GROUP_ID,
    MOUNT_ID,
    INODE_NUM,
    TGT_INODE_NUM,
    SRC_INODE_NUM,
    DEST_INODE_NUM,
    ROOT_DIR_INODE_NUM,
    BASENAME,
    SRC_BASENAME,
    DEST_BASENAME,
    FULLPATH,
    TGT_FULLPATH,
    DST_FULLPATH,
    OFFSET,
    LENGTH,
    TARGET,
    NEW_SIZE,
    FILE_TYPE,
    USED_BYTES,
    NUM_FILES,
    NUM_DIRS,
    NUM_ENTRIES,
    ARE_MORE_ENTRIES,
    CREATE_TIME,
    CTIME,
    CRTIME,
    MTIME,
    ATIME,
    NUM_LINKS,
    STAT_INUM,
    SIZE,
    BUF,
    PREV_BASENAME_RET,
    MAX_ENTRIES,
    MAX_BUFSIZE,
    DIRENTS,
    STATENTS,
    MESSAGE,
    USERID,
    GROUPID,
    MODE,
    ATTRNAME,
    ATTRVALUE,
    ATTRVALUESIZE,
    ATTRFLAGS,
    ATTRNAMES,
    ATTRNNAMESCOUNT,
    NEXT_DIR_LOCATION,
    PREV_DIR_ENT_LOCATION,
    PREV_DIR_ENT_NAME,
    BLOCK_SIZE,
    FRAGMENT_SIZE,
    TOTAL_BLOCKS,
    FREE_BLOCKS,
    AVAIL_BLOCKS,
    TOTAL_INODES,
    FREE_INODES,
    AVAIL_INODES,
    FILESYSTEM_ID,
    MOUNT_FLAGS,
    MAX_FILENAME_LEN,
    FLOCK_CMD,
    FLOCK_TYPE,
    FLOCK_WHENCE,
    FLOCK_START,
    FLOCK_LEN,
    FLOCK_PID,
    SEND_TIME_SEC,
    SEND_TIME_NSEC,
    REC_TIME_SEC,
    REC_TIME_NSEC,
    PING_MESSAGE,
} rpc_param_t;


// Global to hold param enum-to-string translation table
char* ptable[] = {
    "VolumeName",           // VOL_NAME
    "MountOptions",         // MOUNT_OPTS
    "AuthUserID",           // AUTH_USER_ID
    "AuthGroupID",          // AUTH_GROUP_ID
    "MountID",              // MOUNT_ID
    "InodeNumber",          // INODE_NUM
    "TargetInodeNumber",    // TGT_INODE_NUM
    "SrcDirInodeNumber",    // SRC_INODE_NUM
    "DstDirInodeNumber",    // DEST_INODE_NUM
    "RootDirInodeNumber",   // ROOT_DIR_INODE_NUM
    "Basename",             // BASENAME
    "SrcBasename",          // SRC_BASENAME
    "DstBasename",          // DEST_BASENAME
    "Fullpath",             // FULLPATH
    "TargetFullpath",       // TGT_FULLPATH
    "DstFullpath",          // DST_FULLPATH
    "Offset",               // OFFSET
    "Length",               // LENGTH
    "Target",               // TARGET
    "NewSize",              // NEW_SIZE
    "FileType",             // FILE_TYPE
    "UsedBytes",            // USED_BYTES
    "NumFiles",             // NUM_FILES
    "NumDirs",              // NUM_DIRS
    "NumEntries",           // NUM_ENTRIES
    "AreMoreEntries",       // ARE_MORE_ENTRIES
    "CreateTime",           // CREATE_TIME
    "CTimeNs",              // CTIME
    "CRTimeNs",             // CRTIME
    "MTimeNs",              // MTIME
    "ATimeNs",              // ATIME
    "NumLinks",             // NUM_LINKS
    "StatInodeNumber",      // STAT_INUM
    "Size",                 // SIZE
    "Buf",                  // BUF
    "PrevBasenameReturned", // PREV_BASENAME_RET
    "MaxEntries",           // MAX_ENTRIES
    "MaxBufsize",           // MAX_BUFSIZE
    "DirEnts",              // DIRENTS
    "StatEnts",             // STATENTS
    "Message",              // MESSAGE
    "UserID",               // USERID
    "GroupID",              // GROUPID
    "FileMode",             // MODE
    "AttrName",             // ATTRNAME
    "AttrValue",            // ATTRVALUE
    "AttrValueSize",        // ATTRVALUESIZE
    "AttrFlags",            // ATTRFLAGS
    "AttrNames",            // ATTRNAMES
    "AttrNamesCount",       // ATTRNNAMESCOUNT
    "NextDirLocation",      // NEXT_DIR_LOCATION
    "PrevDirEntLocation",   // PREV_DIR_ENT_LOCATION
    "PrevDirEntName",       // PREV_DIR_ENT_NAME
    "BlockSize",            // BLOCK_SIZE
    "FragmentSize",         // FRAGMENT_SIZE
    "TotalBlocks",          // TOTAL_BLOCKS
    "FreeBlocks",           // FREE_BLOCKS
    "AvailBlocks",          // AVAIL_BLOCKS
    "TotalInodes",          // TOTAL_INODES
    "FreeInodes",           // FREE_INODES
    "AvailInodes",          // AVAIL_INODES
    "FileSystemID",         // FILESYSTEM_ID
    "MountFlags",           // MOUNT_FLAGS
    "MaxFilenameLen",       // MAX_FILENAME_LEN
    "FlockCmd",             // FLOCK_CMD
    "FlockType",            // FLOCK_TYPE
    "FlockWhence",          // FLOCK_WHENCE
    "FlockStart",           // FLOCK_START
    "FlockLen",             // FLOCK_LEN
    "FlockPid",             // FLOCK_PID
    "SendTimeSec",          // SEND_TIME_SEC
    "SendTimeNsec",         // SEND_TIME_NSEC
    "RequestTimeSec",       // REC_TIME_SEC
    "RequestTimeNsec",      // REC_TIME_NSEC
    "Message",              // PING_MESSAGE
};


void handle_rsp_error(const char* callingFunc, int* rsp_err, mount_handle_t* mount_handle) {
    if (debug_flag>0) printf("  [%p] %s: %s returned error=%d.\n", ((void*)((uint64_t)pthread_self())), __FUNCTION__, callingFunc , *rsp_err);

    if (*rsp_err == EINVAL) {
        // If we got this error here, it is from the far end.
        // This error means that our mount ID was not recognized.
        // This can happen if proxyfsd went down and came back up,
        // since it does not persist mount IDs.

        // NOTE:
        // For now we will fetch and update the mount ID in the
        // mount handle. In the future, we may want to consider
        // moving to a persisted volume ID/handle.

        // Call the RPC to do the mount
        int rsp_status = proxyfs_remount(mount_handle);
        if (rsp_status != 0) {
            DPRINTF("error=%d was returned from proxyfs_remount.\n",rsp_status);
        } else {
            DPRINTF("remount returned mount id=%zu.\n",mount_handle->mount_id_as_str);
        }
//        // Call the RPC to do the mount
//        int rsp_status = proxyfs_remount_async(mount_handle);
//        if (rsp_status != 0) {
//            DPRINTF("error=%d was returned from proxyfs_remount.\n",rsp_status);
//        }
    }

    if (*rsp_err == EPIPE) {
        // We use EPIPE here to indicate that we had a socket communication
        // problem on this end. This allows us to distinguish in this file
        // from bad-mount-id EINVAL from the far end.
        //
        // Since EPIPE is not one of our API errors, convert it now to ENODEV
        *rsp_err = ENODEV;
    }
}

int proxyfs_chmod(mount_handle_t* in_mount_handle,
                  uint64_t        in_inode_number,
                  mode_t          in_mode)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcChmod");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_int   (ctx, ptable[MODE],      in_mode);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_chmod_path(mount_handle_t* in_mount_handle,
                       char*           in_fullpath,
                       mode_t          in_mode)
{
    // NOTE: The effective UID of the calling process must match the owner of the file.
    if ((in_mount_handle == NULL) ||(in_fullpath == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcChmodPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    jsonrpc_set_req_param_int(ctx, ptable[MODE],     in_mode);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_chown(mount_handle_t* in_mount_handle,
                  uint64_t        in_inode_number,
                  uid_t           in_owner,
                  gid_t           in_group)
{
    // NOTE: If the owner or group is specified as -1, then that ID is not changed.

    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Caller can use -1 or 0 as a owner or group value, to indicate that they don't
    // want to set it. However one of the two needs to be set.
    if ((in_owner == -1) && (in_group == -1)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcChown");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_int   (ctx, ptable[USERID],    in_owner);
    jsonrpc_set_req_param_int   (ctx, ptable[GROUPID],   in_group);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_chown_path(mount_handle_t* in_mount_handle,
                       char*           in_fullpath,
                       uid_t           in_owner,
                       gid_t           in_group)
{
    // NOTE: If the owner or group is specified as -1, then that ID is not changed.
    if ((in_mount_handle == NULL) ||(in_fullpath == NULL)) {
        return EINVAL;
    }

    if ((in_owner == -1) && (in_group == -1)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcChownPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    jsonrpc_set_req_param_int(ctx, ptable[USERID],   in_owner);
    jsonrpc_set_req_param_int(ctx, ptable[GROUPID],  in_group);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_create(mount_handle_t* in_mount_handle,
                   uint64_t        in_inode_number,
                   char*           in_basename,
                   uid_t           in_uid,
                   gid_t           in_gid,
                   mode_t          in_mode,
                   uint64_t*       out_inode_number)
{
    if ((in_mount_handle == NULL) || (out_inode_number == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcCreate");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[BASENAME],  in_basename);
    jsonrpc_set_req_param_int   (ctx, ptable[USERID],    in_uid);
    jsonrpc_set_req_param_int   (ctx, ptable[GROUPID],   in_gid);
    jsonrpc_set_req_param_int   (ctx, ptable[MODE],      in_mode);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        *out_inode_number = jsonrpc_get_resp_uint64(ctx, ptable[INODE_NUM]);
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_create_path(mount_handle_t* in_mount_handle,
                        char*           in_fullpath,
                        uid_t           in_uid,
                        gid_t           in_gid,
                        mode_t          in_mode,
                        uint64_t*       out_inode_number)
{
    if ((in_mount_handle == NULL) || (out_inode_number == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcCreatePath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    jsonrpc_set_req_param_int(ctx, ptable[USERID],   in_uid);
    jsonrpc_set_req_param_int(ctx, ptable[GROUPID],  in_gid);
    jsonrpc_set_req_param_int(ctx, ptable[MODE],     in_mode);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        *out_inode_number = jsonrpc_get_resp_uint64(ctx, ptable[INODE_NUM]);
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_flock(mount_handle_t* in_mount_handle,
                  uint64_t       in_inode_number,
                  int            in_lock_cmd,
                  struct flock*  flock)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    if (flock->l_pid == 0) {
        return EINVAL;
    }

   // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcFlock");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],     in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM],    in_inode_number);
    jsonrpc_set_req_param_int   (ctx, ptable[FLOCK_CMD],    in_lock_cmd);
    jsonrpc_set_req_param_int   (ctx, ptable[FLOCK_TYPE],   flock->l_type);
    jsonrpc_set_req_param_int   (ctx, ptable[FLOCK_WHENCE], flock->l_whence);
    jsonrpc_set_req_param_uint64(ctx, ptable[FLOCK_START],  flock->l_start);
    jsonrpc_set_req_param_uint64(ctx, ptable[FLOCK_LEN],    flock->l_len);
    jsonrpc_set_req_param_uint64(ctx, ptable[FLOCK_PID],    flock->l_pid);

    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    if ((rsp_status == 0) || (rsp_status == EAGAIN)) {
        flock->l_type   = jsonrpc_get_resp_int   (ctx, ptable[FLOCK_TYPE]);
        flock->l_whence = jsonrpc_get_resp_int   (ctx, ptable[FLOCK_WHENCE]);
        flock->l_start  = jsonrpc_get_resp_uint64(ctx, ptable[FLOCK_START]);
        flock->l_len    = jsonrpc_get_resp_uint64(ctx, ptable[FLOCK_LEN]);
        flock->l_pid    = jsonrpc_get_resp_uint64(ctx, ptable[FLOCK_PID]);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_flush(mount_handle_t* in_mount_handle,
                  uint64_t        in_inode_number)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Start timing
    profiler_t*  profiler  = NewProfiler(FLUSH);

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcFlush");
    jsonrpc_set_profiler(ctx, profiler);

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);

    // Add timestamp of when we sent the request
    struct timespec sendTimeUnix;
    clock_gettime(CLOCK_REALTIME, &sendTimeUnix);
    jsonrpc_set_req_param_int64(ctx, ptable[SEND_TIME_SEC],  sendTimeUnix.tv_sec);
    jsonrpc_set_req_param_int64(ctx, ptable[SEND_TIME_NSEC], sendTimeUnix.tv_nsec);
    AddProfilerEventTime(profiler, RPC_SEND_TIMESTAMP, sendTimeUnix);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    struct timespec respTimeUnix;
    clock_gettime(CLOCK_REALTIME, &respTimeUnix);

    struct timespec rspSendTime;
    struct timespec reqRecTime;
    if (rsp_status == 0) {
        // Success
        rspSendTime.tv_sec  = jsonrpc_get_resp_int64(ctx, ptable[SEND_TIME_SEC]);
        rspSendTime.tv_nsec = jsonrpc_get_resp_int64(ctx, ptable[SEND_TIME_NSEC]);
        reqRecTime.tv_sec   = jsonrpc_get_resp_int64(ctx, ptable[REC_TIME_SEC]);
        reqRecTime.tv_nsec  = jsonrpc_get_resp_int64(ctx, ptable[REC_TIME_NSEC]);

        int64_t reqDelivLatencyNs =  diffNs(reqRecTime, sendTimeUnix);
        int64_t respDelivLatencyNs = diffNs(rspSendTime, respTimeUnix);

        //PRINTF("rspSendTime.tv_sec = %ld tv_nsec = %ld respDelivLatency = %ld us\n",
        //       rspSendTime.tv_sec, rspSendTime.tv_nsec, respDelivLatencyNs/1000);
        //PRINTF("reqRecTime.tv_sec = %ld tv_nsec = %ld reqDelivLatency = %ld us (%ld ns)\n",
        //       reqRecTime.tv_sec, reqRecTime.tv_nsec, reqDelivLatencyNs/1000, reqDelivLatencyNs);

        // Add timestamp for when ProxyFS sent the response.
        // We record when we received it as AFTER_RPC.
        AddProfilerEventTime(profiler, RPC_RESP_SEND_TIME, rspSendTime);

        // Now add an event for the request receive time
        AddProfilerEventTime(profiler, RPC_REQ_DELIVERY_TIME, reqRecTime);

        //PRINTF("reqDeliveryTime.tv_sec = %ld tv_nsec = %ld\n",
        //       sendTimeUnix.tv_sec, sendTimeUnix.tv_nsec);

    } else {
        // Special handling for read/write/flush: translate ENOENT to EBADF
        if (rsp_status == ENOENT) {
            rsp_status = EBADF;
        }

        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }
    AddProfilerEventTime(profiler, AFTER_RPC, respTimeUnix);

    // Stop timing and print latency
    StopProfiler(profiler);
    //PRINTF("inode=%ld; latency: %ld us, status=%d\n",
    //       in_inode_number, ElapsedUs(stopwatch), rsp_status);
    DumpProfiler(profiler);
    DeleteProfiler(profiler);

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

void nanosec_to_timespec(uint64_t nanoSinceEpoch, proxyfs_timespec_t* timespec)
{
    timespec->sec  = nanoSinceEpoch / 1000000000ULL;
    timespec->nsec = nanoSinceEpoch % 1000000000ULL;
}

uint64_t timespec_to_nanosec(proxyfs_timespec_t* timespec)
{
    uint64_t nanoSinceEpoch = timespec->sec * 1000000000ULL + timespec->nsec;
    return nanoSinceEpoch;
}

// For non-array response structures, call with array_key = NULL.
void stat_resp_to_struct(jsonrpc_context_t* ctx, proxyfs_stat_t* stat, char* array_key, int array_index)
{
    // File mode
    stat->mode = jsonrpc_get_resp_array_int(ctx, array_key, array_index, ptable[MODE]);

    // Inode number
    stat->ino = jsonrpc_get_resp_array_uint64(ctx, array_key, array_index, ptable[STAT_INUM]);

    // Device containing file doesn't really mean anything here, so
    // default to zero.
    stat->dev    = 0;

    // Number of hard links
    stat->nlink  = jsonrpc_get_resp_array_uint64(ctx, array_key, array_index, ptable[NUM_LINKS]);

    // User and group id. We are defaulting these to 0 (superuser).
    stat->uid = jsonrpc_get_resp_array_int(ctx, array_key, array_index, ptable[USERID]);
    stat->gid = jsonrpc_get_resp_array_int(ctx, array_key, array_index, ptable[GROUPID]);

    // File size
    stat->size   = jsonrpc_get_resp_array_uint64(ctx, array_key, array_index, ptable[SIZE]);

    // Set time-related values
    nanosec_to_timespec(jsonrpc_get_resp_array_uint64(ctx, array_key, array_index, ptable[CTIME]),  &stat->ctim);
    nanosec_to_timespec(jsonrpc_get_resp_array_uint64(ctx, array_key, array_index, ptable[CRTIME]), &stat->crtim);
    nanosec_to_timespec(jsonrpc_get_resp_array_uint64(ctx, array_key, array_index, ptable[MTIME]),  &stat->mtim);
    nanosec_to_timespec(jsonrpc_get_resp_array_uint64(ctx, array_key, array_index, ptable[ATIME]),  &stat->atim);
}


int proxyfs_get_stat(mount_handle_t*  in_mount_handle,
                     uint64_t         in_inode_number,
                     proxyfs_stat_t** out_stat)
{
    if ((in_mount_handle == NULL) && (out_stat != NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcGetStat");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        //
        // First alloc a struct to fill in and set it to be returned
        proxyfs_stat_t* stat = (proxyfs_stat_t*)malloc(sizeof(proxyfs_stat_t));
        *out_stat = stat;

        // Now fill in the struct
        stat_resp_to_struct(ctx, stat, NULL, 0);

    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_get_stat_path(mount_handle_t*  in_mount_handle,
                          char*            in_fullpath,
                          proxyfs_stat_t** out_stat)
{
    if ((in_mount_handle == NULL) && (out_stat != NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcGetStatPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        //
        // First alloc a struct to fill in and set it to be returned
        proxyfs_stat_t* stat = (proxyfs_stat_t*)malloc(sizeof(proxyfs_stat_t));
        *out_stat = stat;

        // Now fill in the struct
        stat_resp_to_struct(ctx, stat, NULL, 0);

    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

static int proxyfs_get_xattr1(mount_handle_t* in_mount_handle,
                              char*           in_fullpath,
                              uint64_t        in_inode_number,
                              const char*     in_attr_name,
                              void*           out_attr_value,
                              size_t*         out_attr_value_size)
{
    if ((in_mount_handle == NULL) && (out_attr_value != NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = NULL;

    if (in_fullpath == NULL) {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcGetXAttr");
        jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    } else {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcGetXAttrPath");
        jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    }

    jsonrpc_set_req_param_str   (ctx, ptable[ATTRNAME],  (char *)in_attr_name);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {

        size_t local_out_attr_value_size = jsonrpc_get_resp_uint64(ctx, ptable[ATTRVALUESIZE]);

        // Return now if no values
        if (local_out_attr_value_size == 0) {
            *out_attr_value_size = 0;
            jsonrpc_close(ctx);
            return rsp_status;
        }

        // The caller passes 0 if they want to know how much to allocate
        // before calling with the proper size.
        if (*out_attr_value_size == 0) {
            *out_attr_value_size = local_out_attr_value_size;
            jsonrpc_close(ctx);
            return rsp_status;
        }

        // At this point, they should have passed a buffer.  Make sure it
        // it is not NULL.
        if (out_attr_value == NULL) {
            rsp_status = EFAULT;
            jsonrpc_close(ctx);
            return rsp_status;
        }

        // Check if enough space to store values
        if (local_out_attr_value_size > *out_attr_value_size) {
            rsp_status = ERANGE;
            jsonrpc_close(ctx);
            return rsp_status;
        }

        size_t bytes_written;
        jsonrpc_get_resp_buf(ctx, ptable[ATTRVALUE], out_attr_value, *out_attr_value_size, &bytes_written);
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_get_xattr(mount_handle_t* in_mount_handle,
                     uint64_t         in_inode_number,
                     const char*      in_attr_name,
                     void*            out_attr_value,
                     size_t*          out_attr_value_size)
{
    return proxyfs_get_xattr1(in_mount_handle, NULL,in_inode_number, in_attr_name, out_attr_value, out_attr_value_size);

}

int proxyfs_get_xattr_path(mount_handle_t* in_mount_handle,
                          char*            in_fullpath,
                          const char*      in_attr_name,
                          void*            out_attr_value,
                          size_t*          out_attr_value_size)
{
    if (in_fullpath == NULL) {
        return EINVAL;
    }

    return proxyfs_get_xattr1(in_mount_handle, in_fullpath, 0, in_attr_name, out_attr_value, out_attr_value_size);
}

int proxyfs_link(mount_handle_t* in_mount_handle,
                 uint64_t        in_inode_number,
                 char*           in_basename,
                 uint64_t        in_target_inode_number)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcLink");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],      in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM],     in_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[BASENAME],      in_basename);
    jsonrpc_set_req_param_uint64(ctx, ptable[TGT_INODE_NUM], in_target_inode_number);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_link_path(mount_handle_t* in_mount_handle,
                      char*           in_src_fullpath,
                      char*           in_tgt_fullpath)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcLinkPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID],     in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH],     in_src_fullpath);
    jsonrpc_set_req_param_str(ctx, ptable[TGT_FULLPATH], in_tgt_fullpath);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

// Internal list_xattr funcionction. If in_fullpath is specified it will be used ontherwise in_inode_number will be used.`
static int proxyfs_list_xattr1(mount_handle_t* in_mount_handle,
                               char            *in_fullpath,
                               uint64_t        in_inode_number,
                               char**          out_attr_list,
                               size_t*         out_attr_list_size)
{
    if ((in_mount_handle == NULL) && (out_attr_list != NULL)) {
        return EINVAL;
    }

    jsonrpc_context_t* ctx = NULL;

    if (in_fullpath == NULL) {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcListXAttr");
        jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    } else {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcListXAttrPath");
        jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    }

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        *out_attr_list_size = 0;

        int num_entries = jsonrpc_get_resp_array_length(ctx, ptable[ATTRNAMES]);
        if (num_entries <= 0) {
            jsonrpc_close(ctx);
            return rsp_status;
        }

        *out_attr_list_size = (size_t)num_entries;

        out_attr_list = (char **)malloc((*out_attr_list_size) * sizeof(char *));
        int i = 0;
        for (i = 0; i < *out_attr_list_size; i++) {
            out_attr_list[i] = (char *)jsonrpc_get_resp_array_str_value(ctx, ptable[ATTRNAMES], i);
        }
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_list_xattr(mount_handle_t* in_mount_handle,
                       uint64_t        in_inode_number,
                       char**          out_attr_list,
                       size_t*         out_attr_list_size)
{
    return proxyfs_list_xattr1(in_mount_handle, NULL, in_inode_number, out_attr_list, out_attr_list_size);
}

int proxyfs_list_xattr_path(mount_handle_t* in_mount_handle,
                            char*           in_fullpath,
                            char**          out_attr_list,
                            size_t*         out_attr_list_size)
{
    if (in_fullpath == NULL) {
        return EINVAL;
    }
    return proxyfs_list_xattr1(in_mount_handle, in_fullpath, 0, out_attr_list, out_attr_list_size);
}


int proxyfs_log(mount_handle_t* in_mount_handle,
                char*           in_message)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcLog");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MESSAGE], in_message);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_lookup(mount_handle_t* in_mount_handle,
                   uint64_t        in_inode_number,
                   char*           in_basename,
                   uint64_t*       out_inode_number)
{
    if ((in_mount_handle == NULL) || (out_inode_number == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcLookup");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[BASENAME],  in_basename);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        *out_inode_number = jsonrpc_get_resp_uint64(ctx, ptable[INODE_NUM]);
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_lookup_path(mount_handle_t* in_mount_handle,
                        char*           in_fullpath,
                        uint64_t*       out_inode_number)
{
    if ((in_mount_handle == NULL) || (out_inode_number == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcLookupPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        *out_inode_number = jsonrpc_get_resp_uint64(ctx, ptable[INODE_NUM]);
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_mkdir(mount_handle_t* in_mount_handle,
                  uint64_t        in_inode_number,
                  char*           in_basename,
                  uid_t           in_uid,
                  gid_t           in_gid,
                  mode_t          in_mode,
                  uint64_t*       out_inode_number)
{
    if ((in_mount_handle == NULL) || (out_inode_number == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcMkdir");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[BASENAME],  in_basename);
    jsonrpc_set_req_param_int   (ctx, ptable[USERID],    in_uid);
    jsonrpc_set_req_param_int   (ctx, ptable[GROUPID],   in_gid);
    jsonrpc_set_req_param_int   (ctx, ptable[MODE],      in_mode);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        *out_inode_number = jsonrpc_get_resp_uint64(ctx, ptable[INODE_NUM]);
        DPRINTF("Returned %s: %" PRIu64 "\n", ptable[INODE_NUM], *out_inode_number);

    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_mkdir_path(mount_handle_t* in_mount_handle,
                       char*           in_fullpath,
                       uid_t           in_uid,
                       gid_t           in_gid,
                       mode_t          in_mode)
{
    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcMkdirPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    jsonrpc_set_req_param_int(ctx, ptable[USERID],   in_uid);
    jsonrpc_set_req_param_int(ctx, ptable[GROUPID],  in_gid);
    jsonrpc_set_req_param_int(ctx, ptable[MODE],     in_mode);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_mount(char*            in_volume_name,
                  uint64_t         in_mount_options,
                  uint64_t         in_auth_user_id,
                  uint64_t         in_auth_group_id,
                  mount_handle_t** out_mount_handle)
{
    if ((out_mount_handle == NULL) || (in_volume_name == NULL)) {
        return EINVAL;
    }

    if ((in_volume_name != NULL) && (strlen(in_volume_name) > MAX_VOL_NAME_LENGTH)) {
        DPRINTF("Error, volume name %s is longer than max length of %d.\n",in_volume_name,MAX_VOL_NAME_LENGTH);
        return EINVAL;
    }

    // Alloc memory for handle to return and fill it in
    //
    // NOTE: The memory allocated for this handle is freed in proxyfs_unmount.
    //
    mount_handle_t* handle     = (mount_handle_t*)malloc(sizeof(mount_handle_t));
    handle->rpc_handle         = pfs_rpc_open();  // XXX TODO: move inside proxyfs_jsonrpc.c?
    handle->mount_id_as_str    = NULL;
    handle->root_dir_inode_num = 0;
    handle->mount_options      = in_mount_options;
    handle->auth_user_id       = in_auth_user_id;
    handle->auth_group_id      = in_auth_group_id;

    strncpy(handle->volume_name, in_volume_name, MAX_VOL_NAME_LENGTH);
    handle->volume_name[MAX_VOL_NAME_LENGTH-1] = 0;

    // Check that we were able to open an RPC connection to the server
    if (handle->rpc_handle == NULL) {
        DPRINTF("error opening RPC connection to server.\n");

        // Free the memory we allocated since we won't be using it
        free(handle);

        // Set mount handle to null and return
        *out_mount_handle = NULL;

        return ENODEV;
    }

    // Set mount handle
    *out_mount_handle = handle;

    // Call the RPC to do the mount
    int rsp_status = proxyfs_remount(handle);
    if (rsp_status != 0) {
        DPRINTF("error=%d was returned.\n", rsp_status);

        // XXX TODO: No longer doing this, since we want to reuse
        //           the underlying socket handles across mounts.
        //
        // Call unmount to shut down RPC and free the handle
        //proxyfs_unmount(handle);

        // Set mount handle to null and return
        *out_mount_handle = NULL;
    }

    return rsp_status;
}

// This is an internal function, used to fetch the mount ID after
// we have had a problem communicating over the socket, or to fetch
// it in the first place.
//
// This breaks our alphabetical ordering convention, but it's good to
// have this API near proxyfs_mount.
//
int proxyfs_remount(mount_handle_t* in_mount_handle)
{
    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcMountByVolumeName");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(   ctx, ptable[VOL_NAME],      in_mount_handle->volume_name);
    jsonrpc_set_req_param_int(   ctx, ptable[MOUNT_OPTS],    in_mount_handle->mount_options);
    jsonrpc_set_req_param_uint64(ctx, ptable[AUTH_USER_ID],  in_mount_handle->auth_user_id);
    jsonrpc_set_req_param_uint64(ctx, ptable[AUTH_GROUP_ID], in_mount_handle->auth_group_id);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the return values (assuming .mount_id_as_str decodes)
        in_mount_handle->mount_id_as_str    = strdup(jsonrpc_get_resp_str(ctx, ptable[MOUNT_ID]));
        in_mount_handle->root_dir_inode_num = jsonrpc_get_resp_uint64(ctx, ptable[ROOT_DIR_INODE_NUM]);

        rsp_status = proxyfs_decode_mount_id(in_mount_handle);
        if (rsp_status != 0) {
            handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
        }
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

// proxyfs_base64_decode_table is used in proxyfs_decode_mount_id
//
static const uint8_t proxyfs_base64_decode_table[256] =
{
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 00-0F
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 10-1F
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63, // 20-2F
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64,  0, 64, 64, // 30-3F - Ascii '=' decodes as zero 6-bits
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 40-4F
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64, // 50-5F
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 60-6F
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64, // 70-7F
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 80-8F
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // 90-9F
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // A0-AF
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // B0-BF
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // C0-CF
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // D0-DF
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, // E0-EF
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64  // F0-FF
};

// proxyfs_decode_mount_id decodes the Base64-encoded .mount_id_as_str field
// into the binary .mount_id_as_mount_id_as_bytes field.
//
// Returns:
//   0 if successful
//   ENOENT if unsuccessful
//
int proxyfs_decode_mount_id(mount_handle_t *in_mount_handle)
{
    int      as_bytes_index;
    uint32_t as_bytes_u24;
    int      as_str_index;
    int      as_str_len_actual;
    int      as_str_len_expected;
    int      as_str_trailing_pad_chars_expected;
    uint8_t  decoded_u6;

    as_str_len_actual = strlen(in_mount_handle->mount_id_as_str);

    switch (MOUNT_ID_SIZE % 3) {
        case 0:
            as_str_len_expected                = ((MOUNT_ID_SIZE + 0) / 3) * 4;
            as_str_trailing_pad_chars_expected = 0;
            break;
        case 1:
            as_str_len_expected                = ((MOUNT_ID_SIZE + 2) / 3) * 4;
            as_str_trailing_pad_chars_expected = 2;
            break;
        case 2:
            as_str_len_expected                = ((MOUNT_ID_SIZE + 1) / 3) * 4;
            as_str_trailing_pad_chars_expected = 1;
            break;
    }

    if (as_str_len_actual != as_str_len_expected) {
        return ENOENT;
    }

    if (as_str_trailing_pad_chars_expected > 0) {
        if ('=' != in_mount_handle->mount_id_as_str[as_str_len_actual-1]) {
            return ENOENT;
        }
        if (as_str_trailing_pad_chars_expected == 2) {
            if ('=' != in_mount_handle->mount_id_as_str[as_str_len_actual-2]) {
                return ENOENT;
            }
        }
    }

    as_bytes_index = 0;

    for (as_str_index = 0;;as_str_index += 4) {
        decoded_u6 = proxyfs_base64_decode_table[in_mount_handle->mount_id_as_str[as_str_index+0]];
        if (decoded_u6 > 63) return ENOENT; // FAILED
        as_bytes_u24 = (uint32_t)decoded_u6;
        decoded_u6 = proxyfs_base64_decode_table[in_mount_handle->mount_id_as_str[as_str_index+1]];
        if (decoded_u6 > 63) return ENOENT; // FAILED
        as_bytes_u24 = (as_bytes_u24 << 6) | (uint32_t)decoded_u6;
        decoded_u6 = proxyfs_base64_decode_table[in_mount_handle->mount_id_as_str[as_str_index+2]];
        if (decoded_u6 > 63) return ENOENT; // FAILED
        as_bytes_u24 = (as_bytes_u24 << 6) | (uint32_t)decoded_u6;
        decoded_u6 = proxyfs_base64_decode_table[in_mount_handle->mount_id_as_str[as_str_index+3]];
        if (decoded_u6 > 63) return ENOENT; // FAILED
        as_bytes_u24 = (as_bytes_u24 << 6) | (uint32_t)decoded_u6;
        in_mount_handle->mount_id_as_bytes[as_bytes_index++] = (uint8_t)((as_bytes_u24 & 0xFF0000) >> 16);
        if (as_bytes_index == MOUNT_ID_SIZE) return 0; // SUCCESS
        in_mount_handle->mount_id_as_bytes[as_bytes_index++] = (uint8_t)((as_bytes_u24 & 0x00FF00) >>  8);
        if (as_bytes_index == MOUNT_ID_SIZE) return 0; // SUCCESS
        in_mount_handle->mount_id_as_bytes[as_bytes_index++] = (uint8_t)((as_bytes_u24 & 0x0000FF) >>  0);
        if (as_bytes_index == MOUNT_ID_SIZE) return 0; // SUCCESS
    }

    // No way to reach here... as_str_index loop is unterminated but MOUNT_ID_SIZE limits as_bytes_index
}

int proxyfs_ping(mount_handle_t* in_mount_handle, char* in_ping_message)
{
    if ((in_mount_handle == NULL) || (in_ping_message == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcPing");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MESSAGE], in_ping_message);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

// Reads precisely the specified length of data from sockfd
//
// Returns either:
//   0: requested number of bytes copied from sockfd to bufptr
//   otherwise: errno
int read_from_socket(int sockfd, void *bufptr, int length) {
    int ret = 0;
    int total = 0;
    while (total < length) {
        char *addr = bufptr + total;
        ret = read(sockfd, addr, length - total);
        if (ret < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            return -errno;
        }

        if (ret == 0) {
            DPRINTF("proxyfsd server side disconnected while reading reply from socket.\n");
            return -EPIPE;
        }
        total += ret;
    }

    return 0;
}

// Writes precisely the specified length of data to sockfd
//
// Returns either:
//   0: requested number of bytes copied from bufptr to sockfd
//   otherwise: errno
int write_to_socket(int sockfd, void *bufptr, int length) {
    int ret = 0;
    int total = 0;
    while (total < length) {
        char *addr = bufptr + total;
        ret = write(sockfd, addr, length - total);
        if (ret < 0) {
            if (errno == EAGAIN) {
                continue;
            }
            return -errno;
        }
        total += ret;
    }

    return 0;
}

void dump_io_req(proxyfs_io_request_t req, const char* prefix)
{
    DPRINTF("%s: req is:\n", prefix);
    DPRINTF("    .op           = %d\n",  req.op);
    DPRINTF("    .mount_handle = %p\n",  req.mount_handle);
    DPRINTF("    .inode_number = %ld\n", req.inode_number);
    DPRINTF("    .offset       = %ld\n", req.offset);
    DPRINTF("    .length       = %ld\n", req.length);
    DPRINTF("    .data         = %p\n",  req.data);
    DPRINTF("    .error        = %d\n",  req.error);
    DPRINTF("    .out_size     = %ld\n", req.out_size);
}


// NOTE: the proxyfs_read API is currently only called from our test code.
//       Samba vfs calls proxyfs_sync_io instead, which calls proxyfs_read_req.
//
int proxyfs_read(mount_handle_t* in_mount_handle,
                 uint64_t        in_inode_number,
                 uint64_t        in_offset,
                 uint64_t        in_length,
                 uint8_t*        in_bufptr,
                 size_t          in_bufsize,
                 size_t*         out_bufsize)
{
    // Make sure that the buffer is big enough to hold the number of bytes requested
    if ((in_mount_handle == NULL) || (in_bufptr == NULL) || (in_bufsize < in_length)) {
        return EINVAL;
    }
    int rsp_status = 0;

    // Start timing
    profiler_t*  profiler  = NewProfiler(READ);

    if (use_fastpath_for_read) {

        proxyfs_io_request_t req = {
            .op           = IO_READ,
            .mount_handle = in_mount_handle,
            .inode_number = in_inode_number,
            .offset       = in_offset,
            .length       = in_length,
            .data         = in_bufptr,
            .error        = 0,
            .out_size     = 0,
            .done_cb      = NULL,
            .done_cb_arg  = NULL,
            .done_cb_fd   = 0,
        };

        dump_io_req(req, __FUNCTION__);

        DPRINTF("%s: calling proxyfs_read_req.\n", __FUNCTION__);

        // Call the read request handler
        rsp_status = proxyfs_read_req(&req, io_sock_fd);

        // Get the status and size out of the response
        //
        if (rsp_status == 0) {
            // If the request handler didn't return an error, get the status out of the request
            rsp_status = req.error;
        }
        *out_bufsize = req.out_size;
        DPRINTF("proxyfs_read_req returned status=%d, out_bufsize=%ld.\n", rsp_status, *out_bufsize);
        dump_io_req(req, __FUNCTION__);

        if (rsp_status != 0) {
            DPRINTF("%s: status: %d\n", __FUNCTION__, rsp_status);
        }

    } else {

        // Get context and set the method
        jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcRead");
        jsonrpc_set_profiler(ctx, profiler);

        // Set the params based on what was passed in
        jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
        jsonrpc_set_req_param_uint64(ctx, ptable[OFFSET],    in_offset);
        jsonrpc_set_req_param_uint64(ctx, ptable[LENGTH],    in_length);

        // Add timestamp of when we sent the request
        struct timespec sendTimeUnix;
        clock_gettime(CLOCK_REALTIME, &sendTimeUnix);
        jsonrpc_set_req_param_int64(ctx, ptable[SEND_TIME_SEC],  sendTimeUnix.tv_sec);
        jsonrpc_set_req_param_int64(ctx, ptable[SEND_TIME_NSEC], sendTimeUnix.tv_nsec);
        AddProfilerEventTime(profiler, RPC_SEND_TIMESTAMP, sendTimeUnix);

        // Call RPC
        rsp_status = jsonrpc_exec_request_blocking(ctx);
        struct timespec respTimeUnix;
        clock_gettime(CLOCK_REALTIME, &respTimeUnix);

        struct timespec rspSendTime;
        struct timespec reqRecTime;
        if (rsp_status == 0) {
            // Success; Set the values to be returned
            //
            jsonrpc_get_resp_buf(ctx, ptable[BUF], in_bufptr, in_bufsize, out_bufsize);
            if (in_bufsize < *out_bufsize) {
                DPRINTF("ERROR, wrote %ld bytes in a buffer of size %ld!\n",
                        *out_bufsize, in_bufsize);
            }

            rspSendTime.tv_sec  = jsonrpc_get_resp_int64(ctx, ptable[SEND_TIME_SEC]);
            rspSendTime.tv_nsec = jsonrpc_get_resp_int64(ctx, ptable[SEND_TIME_NSEC]);
            reqRecTime.tv_sec   = jsonrpc_get_resp_int64(ctx, ptable[REC_TIME_SEC]);
            reqRecTime.tv_nsec  = jsonrpc_get_resp_int64(ctx, ptable[REC_TIME_NSEC]);

            int64_t reqDelivLatencyNs =  diffNs(reqRecTime, sendTimeUnix);
            int64_t respDelivLatencyNs = diffNs(rspSendTime, respTimeUnix);

            //PRINTF("rspSendTime.tv_sec = %ld tv_nsec = %ld respDelivLatency = %ld us\n",
            //       rspSendTime.tv_sec, rspSendTime.tv_nsec, respDelivLatencyNs/1000);
            //PRINTF("reqRecTime.tv_sec = %ld tv_nsec = %ld reqDelivLatency = %ld us (%ld ns)\n",
            //       reqRecTime.tv_sec, reqRecTime.tv_nsec, reqDelivLatencyNs/1000, reqDelivLatencyNs);

            // Add timestamp for when ProxyFS sent the response.
            // We record when we received it as AFTER_RPC.
            AddProfilerEventTime(profiler, RPC_RESP_SEND_TIME, rspSendTime);

            // Now add an event for the request receive time
            AddProfilerEventTime(profiler, RPC_REQ_DELIVERY_TIME, reqRecTime);

            //PRINTF("reqDeliveryTime.tv_sec = %ld tv_nsec = %ld\n",
            //       sendTimeUnix.tv_sec, sendTimeUnix.tv_nsec);

        } else {
            handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
        }
        AddProfilerEventTime(profiler, AFTER_RPC, respTimeUnix);

        // Clean up jsonrpc context and return
        jsonrpc_close(ctx);

    }

done:
    // Stop timing and print latency
    StopProfiler(profiler);
    DumpProfiler(profiler);
    DeleteProfiler(profiler);

    // Special handling for read/write/flush: translate ENOENT to EBADF
    if (rsp_status == ENOENT) {
        rsp_status = EBADF;
    }

    return rsp_status;
}

int proxyfs_read_req(proxyfs_io_request_t *req, int sock_fd)
{
    int           sock_ret;
    io_req_hdr_t  req_hdr = {
            .op_type      = 1002,
            .inode_number = req->inode_number,
            .offset       = req->offset,
            .length       = req->length,
    };
    io_resp_hdr_t resp_hdr;

    (void)memcpy(req_hdr.mount_id, req->mount_handle->mount_id_as_bytes, MOUNT_ID_SIZE);

    if ((req == NULL) || (req->mount_handle == NULL) || (req->data == NULL)) {
        return EINVAL;
    }

    // Start timing
    profiler_t*  profiler  = NewProfiler(READ);

    if ( fail(WRITE_BROKEN_PIPE_FAULT) ) {
        req->error = ENODEV;
        req->out_size = 0;
        goto done;
    }

    // Send request
    sock_ret = write_to_socket(sock_fd, &req_hdr, sizeof(req_hdr));
    if (0 != sock_ret) {
        req->error = EIO;
        goto done;
    }

    // Receive response header
    sock_ret = read_from_socket(sock_fd, &resp_hdr, sizeof(resp_hdr));
    if (0 != sock_ret) {
        req->error = EIO;
        goto done;
    }

    // Receive read data (if any)
    if (0 < resp_hdr.io_size) {
        sock_ret = read_from_socket(sock_fd, req->data, resp_hdr.io_size);
        if (0 != sock_ret) {
            int err = -sock_ret;
            if ((err == EPIPE) || (err == ENODEV) || (err = EBADF)) {
                // TBD: Build a proper error handling mechanism to retry the operation.
                PANIC("Failed to read response from proxyfsd <-> rpc client socket\n");
            }
            req->error = EIO;
            goto done;
        }
    }

    // Set the error to return
    req->error = (int)resp_hdr.error;
    if (0 != req->error) {
        DPRINTF("rpc returned error: %d\n", req->error);
    }

    // Set read data size
    req->out_size = resp_hdr.io_size;

done:
    // Stop timing and print latency
    StopProfiler(profiler);
    DumpProfiler(profiler);
    DeleteProfiler(profiler);

    // Special handling for read/write/flush: translate ENOENT to EBADF
    if (req->error == ENOENT) {
        req->error = EBADF;
    }

    // XXX TODO: why return anything here if it's always zero?
    return 0;
}

struct dirent* proxyfs_get_dirents(jsonrpc_context_t* ctx, int num_entries)
{
    if (0 == jsonrpc_get_resp_array_length(ctx, ptable[DIRENTS])) {
        return (struct dirent *) NULL;
    }

    // NOTE: The caller is responsible for freeing this memory.
    struct dirent* dirents = (struct dirent*)malloc(sizeof(struct dirent) * (num_entries));

    int i=0;
    const char* name = NULL;
    for (i=0; i < num_entries; i++) {
        struct dirent* ent = &dirents[i];
        name = NULL;

        // Get the values for this entry
        //
        ent->d_ino  = jsonrpc_get_resp_array_uint64(ctx, ptable[DIRENTS], i, ptable[INODE_NUM]);
        name        = jsonrpc_get_resp_array_str   (ctx, ptable[DIRENTS], i, ptable[BASENAME]);
        if (name != NULL) {
            strncpy(ent->d_name, name, NAME_MAX);
            // dirent->d_name is NAME_MAX+1 long
            ent->d_name[NAME_MAX] = 0;
        } else {
            DPRINTF("Error getting basename for entry %d!\n",i);
        }

#ifdef _DIRENT_HAVE_D_OFF
        // Directory entry location
        ent->d_off = (int)jsonrpc_get_resp_array_int64(ctx, ptable[DIRENTS], i, ptable[NEXT_DIR_LOCATION]);
#endif

#ifdef _DIRENT_HAVE_D_TYPE
        // File type
        ent->d_type = (int)jsonrpc_get_resp_array_int(ctx, ptable[DIRENTS], i, ptable[FILE_TYPE]);
#endif

#ifdef _DIRENT_HAVE_D_NAMLEN
        ent->d_namlen = strlen(ent->d_name);
#endif

        DPRINTF("entry %d: inode=%" PRIu64 " type=%d basename=%s dir_offset=%d\n",i,
                ent->d_ino, ent->d_type, ent->d_name, (int)ent->d_off);
    }

    return dirents;
}

int proxyfs_readdir_helper(mount_handle_t* in_mount_handle,
                           jsonrpc_context_t* ctx,
                           struct dirent** out_dir_ent)
{
    int out_num_entries = 1;

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        //

        // NOTE: The caller is responsible for freeing this memory.
        *out_dir_ent = proxyfs_get_dirents(ctx, out_num_entries);

        if (NULL == *out_dir_ent) {
            jsonrpc_close(ctx);
            *out_dir_ent = NULL;
            return ENOENT;
        }
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_readdir(mount_handle_t* in_mount_handle,
                    uint64_t        in_inode_number,
                    char*           in_prev_dir_ent_name,
                    struct dirent** out_dir_ent)
{
    if ((in_mount_handle == NULL) || (out_dir_ent == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcReaddir");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],          in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM],         in_inode_number);
    jsonrpc_set_req_param_uint64(ctx, ptable[MAX_ENTRIES],       1);
    jsonrpc_set_req_param_str   (ctx, ptable[PREV_DIR_ENT_NAME], in_prev_dir_ent_name);

    return proxyfs_readdir_helper(in_mount_handle, ctx, out_dir_ent);
}

// NOTE: Unlike readdir(3), caller is responsible for freeing the out_dir_ent.
int proxyfs_readdir_by_loc(mount_handle_t* in_mount_handle,
                           uint64_t        in_inode_number,
                           int64_t         in_prev_dir_ent_location,
                           struct dirent** out_dir_ent)
{
    if ((in_mount_handle == NULL) || (out_dir_ent == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcReaddirByLoc");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],              in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM],             in_inode_number);
    jsonrpc_set_req_param_uint64(ctx, ptable[MAX_ENTRIES],           1);
    jsonrpc_set_req_param_int64 (ctx, ptable[PREV_DIR_ENT_LOCATION], in_prev_dir_ent_location);

    return proxyfs_readdir_helper(in_mount_handle, ctx, out_dir_ent);
}

int proxyfs_readdir_plus_helper(mount_handle_t *in_mount_handle,
                                jsonrpc_context_t *ctx,
                                struct dirent**  out_dir_ent,
                                proxyfs_stat_t** out_dir_ent_stats)
{
    int out_num_entries = 1;

    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        //

        // Alloc and fill in the directory entry info
        *out_dir_ent = proxyfs_get_dirents(ctx, out_num_entries);

        if (NULL == *out_dir_ent) {
            jsonrpc_close(ctx);
            *out_dir_ent = NULL;
            *out_dir_ent_stats = NULL;
            return ENOENT;
        }

        // Alloc and fill in the stat entry info
        //
        // NOTE: The caller is responsible for freeing this memory.
        proxyfs_stat_t* statents = (proxyfs_stat_t*)malloc(sizeof(proxyfs_stat_t) * (out_num_entries));
        *out_dir_ent_stats = statents;

        int i=0;
        for (i=0; i < out_num_entries; i++) {
            // Fill in the stat entry info
            //
            //
            proxyfs_stat_t* stat = &statents[i];

            // Get the values for this entry
            //
            stat_resp_to_struct(ctx, stat, ptable[STATENTS], i);
        }
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_readdir_plus(mount_handle_t*  in_mount_handle,
                         uint64_t         in_inode_number,
                         char*            in_prev_dir_ent_name,
                         struct dirent**  out_dir_ent,
                         proxyfs_stat_t** out_dir_ent_stats)
{

    if ((in_mount_handle == NULL) || (out_dir_ent == NULL) || (out_dir_ent_stats == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcReaddirPlus");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],          in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM],         in_inode_number);
    jsonrpc_set_req_param_uint64(ctx, ptable[MAX_ENTRIES],       1);
    jsonrpc_set_req_param_str   (ctx, ptable[PREV_DIR_ENT_NAME], in_prev_dir_ent_name);

    return proxyfs_readdir_plus_helper(in_mount_handle, ctx, out_dir_ent, out_dir_ent_stats);
}

// NOTE: Unlike readdir(3), caller is responsible for freeing the out_dir_ent and out_dir_ent_stats.
int proxyfs_readdir_plus_by_loc(mount_handle_t*  in_mount_handle,
                                uint64_t         in_inode_number,
                                int64_t          in_prev_dir_ent_loc,
                                struct dirent**  out_dir_ent,
                                proxyfs_stat_t** out_dir_ent_stats)
{
    uint64_t out_num_entries = 1;

    if ((in_mount_handle == NULL) || (out_dir_ent == NULL) || (out_dir_ent_stats == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcReaddirPlusByLoc");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],              in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM],             in_inode_number);
    jsonrpc_set_req_param_uint64(ctx, ptable[MAX_ENTRIES],           1);
    jsonrpc_set_req_param_int64 (ctx, ptable[PREV_DIR_ENT_LOCATION], in_prev_dir_ent_loc);

    return proxyfs_readdir_plus_helper(in_mount_handle, ctx, out_dir_ent, out_dir_ent_stats);
}

int proxyfs_read_symlink(mount_handle_t* in_mount_handle,
                         uint64_t        in_inode_number,
                         const char**    out_target)
{
    if ((in_mount_handle == NULL) || (out_target == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcReadSymlink");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        //
        // Note that memory allocated by any json gets will be
        // cleaned up when we close the jsonrpc context. This
        // means that we need to strdup here if we want the
        // returned value to live after this function returns.
        *out_target = strdup(jsonrpc_get_resp_str(ctx, ptable[TARGET]));
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_read_symlink_path(mount_handle_t* in_mount_handle,
                              char*           in_fullpath,
                              const char**    out_target)
{
    if ((in_mount_handle == NULL) || (out_target == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcReadSymlinkPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        *out_target = strdup(jsonrpc_get_resp_str(ctx, ptable[TARGET]));
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

static int proxyfs_remove_xattr1(mount_handle_t* in_mount_handle,
                              char*           in_fullpath,
                              uint64_t        in_inode_number,
                              const char*     in_attr_name)
{
    if ((in_mount_handle == NULL) && (in_attr_name == NULL)) {
        return EINVAL;
    }

    jsonrpc_context_t* ctx = NULL;

    if (in_fullpath == NULL) {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcRemoveXAttr");
        jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    } else {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcRemoveXAttrPath");
        jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    }

    jsonrpc_set_req_param_str(ctx, ptable[ATTRNAME],  (char *)in_attr_name);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_remove_xattr(mount_handle_t* in_mount_handle,
                         uint64_t        in_inode_number,
                         const char*     in_attr_name)
{
    return proxyfs_remove_xattr1(in_mount_handle, NULL, in_inode_number, in_attr_name);
}

int proxyfs_remove_xattr_path(mount_handle_t* in_mount_handle,
                              char*           in_fullpath,
                              const char*     in_attr_name)
{
    return proxyfs_remove_xattr1(in_mount_handle, in_fullpath, 0, in_attr_name);
}

int proxyfs_rename(mount_handle_t* in_mount_handle,
                   uint64_t        in_src_dir_inode_number,
                   char*           in_src_basename,
                   uint64_t        in_dst_dir_inode_number,
                   char*           in_dst_basename)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcRename");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],       in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[SRC_INODE_NUM],  in_src_dir_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[SRC_BASENAME],   in_src_basename);
    jsonrpc_set_req_param_uint64(ctx, ptable[DEST_INODE_NUM], in_dst_dir_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[DEST_BASENAME],  in_dst_basename);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_rename_path(mount_handle_t* in_mount_handle,
                        char*           in_src_fullpath,
                        char*           in_dst_fullpath)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcRenamePath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID],     in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH],     in_src_fullpath);
    jsonrpc_set_req_param_str(ctx, ptable[DST_FULLPATH], in_dst_fullpath);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_resize(mount_handle_t* in_mount_handle,
                   uint64_t        in_inode_number,
                   uint64_t        in_new_size)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcResize");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_uint64(ctx, ptable[NEW_SIZE],  in_new_size);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_rmdir(mount_handle_t* in_mount_handle,
                  uint64_t        in_inode_number,
                  char*           in_basename)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcRmdir");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[BASENAME],  in_basename);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_rmdir_path(mount_handle_t* in_mount_handle,
                       char*           in_fullpath)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcRmdirPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_setstat(mount_handle_t* in_mount_handle,
                    uint64_t        in_inode_number,
                    uint64_t        in_stat_ctime,
                    uint64_t        in_stat_mtime,
                    uint64_t        in_stat_atime,
                    uint64_t        in_stat_size,
                    uint64_t        in_stat_nlink)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcSetstat");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_uint64(ctx, ptable[CTIME],     in_stat_ctime);
    jsonrpc_set_req_param_uint64(ctx, ptable[MTIME],     in_stat_mtime);
    jsonrpc_set_req_param_uint64(ctx, ptable[ATIME],     in_stat_atime);
    jsonrpc_set_req_param_uint64(ctx, ptable[SIZE],      in_stat_size);
    jsonrpc_set_req_param_uint64(ctx, ptable[NUM_LINKS], in_stat_nlink);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_setattr(mount_handle_t* in_mount_handle,
                    uint64_t        in_inode_number,
                    proxyfs_stat_t* in_attrs,
                    uint32_t        in_mask)
{
    // TBD should be simillar to setstat above..
    return ENOTSUP;
}

int proxyfs_settime(mount_handle_t*      in_mount_handle,
                    uint64_t             in_inode_number,
                    proxyfs_timespec_t*  in_stat_atime,
                    proxyfs_timespec_t*  in_stat_mtime)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcSetTime");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);

    // Convert times to nanosecs since epoch before sending over the wire
    jsonrpc_set_req_param_uint64(ctx, ptable[MTIME], timespec_to_nanosec(in_stat_mtime));
    jsonrpc_set_req_param_uint64(ctx, ptable[ATIME], timespec_to_nanosec(in_stat_atime));

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_settime_path(mount_handle_t*      in_mount_handle,
                         char*                in_fullpath,
                         proxyfs_timespec_t*  in_stat_atime,
                         proxyfs_timespec_t*  in_stat_mtime)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcSetTimePath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);

    // Convert times to nanosecs since epoch before sending over the wire
    jsonrpc_set_req_param_uint64(ctx, ptable[MTIME], timespec_to_nanosec(in_stat_mtime));
    jsonrpc_set_req_param_uint64(ctx, ptable[ATIME], timespec_to_nanosec(in_stat_atime));

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

static int proxyfs_set_xattr1(mount_handle_t* in_mount_handle,
                              char*           in_fullpath,
                              uint64_t        in_inode_number,
                              const char*     in_attr_name,
                              const void*     in_attr_value,
                              size_t          in_attr_size,
                              int             in_attr_flags)
{
    if ((in_mount_handle == NULL) && (in_attr_name == NULL)) {
        return EINVAL;
    }

    jsonrpc_context_t* ctx = NULL;

    if (in_fullpath == NULL) {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcSetXAttr");
        jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    } else {
        ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcSetXAttrPath");
        jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);
    }

    jsonrpc_set_req_param_str(ctx, ptable[ATTRNAME],  (char *)in_attr_name);
    jsonrpc_set_req_param_buf(ctx, ptable[ATTRVALUE], (uint8_t *)in_attr_value, in_attr_size);
    jsonrpc_set_req_param_int(ctx, ptable[ATTRFLAGS], in_attr_flags);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_set_xattr(mount_handle_t* in_mount_handle,
                      uint64_t        in_inode_number,
                      const char*     in_attr_name,
                      const void*     in_attr_value,
                      size_t          in_attr_size,
                      int             in_attr_flags)
{
    return proxyfs_set_xattr1(in_mount_handle, NULL, in_inode_number, in_attr_name, in_attr_value, in_attr_size, in_attr_flags);
}

// Path-based set_xattr
int proxyfs_set_xattr_path(mount_handle_t* in_mount_handle,
                           char*           in_fullpath,
                           const char*     in_attr_name,
                           const void*     in_attr_value,
                           size_t          in_attr_size,
                           int             in_attr_flags)
{
    return proxyfs_set_xattr1(in_mount_handle, in_fullpath, 0, in_attr_name, in_attr_value, in_attr_size, in_attr_flags);
}

struct statvfs* statvfs_resp_to_struct(jsonrpc_context_t* ctx, mount_handle_t* mount_handle)
{
    // First alloc a struct to fill in
    //
    // NOTE: The caller is responsible for freeing this memory.
    struct statvfs* stat = (struct statvfs*)malloc(sizeof(struct statvfs));

    stat->f_bsize   = jsonrpc_get_resp_uint64(ctx, ptable[BLOCK_SIZE]);
    stat->f_frsize  = jsonrpc_get_resp_uint64(ctx, ptable[FRAGMENT_SIZE]);
    stat->f_blocks  = jsonrpc_get_resp_uint64(ctx, ptable[TOTAL_BLOCKS]);
    stat->f_bfree   = jsonrpc_get_resp_uint64(ctx, ptable[FREE_BLOCKS]);
    stat->f_bavail  = jsonrpc_get_resp_uint64(ctx, ptable[AVAIL_BLOCKS]);
    stat->f_files   = jsonrpc_get_resp_uint64(ctx, ptable[TOTAL_INODES]);
    stat->f_ffree   = jsonrpc_get_resp_uint64(ctx, ptable[FREE_INODES]);
    stat->f_favail  = jsonrpc_get_resp_uint64(ctx, ptable[AVAIL_INODES]);
    stat->f_fsid    = jsonrpc_get_resp_uint64(ctx, ptable[FILESYSTEM_ID]);
    stat->f_flag    = jsonrpc_get_resp_uint64(ctx, ptable[MOUNT_FLAGS]);
    stat->f_namemax = jsonrpc_get_resp_uint64(ctx, ptable[MAX_FILENAME_LEN]);

    return stat;
}

int proxyfs_statvfs(mount_handle_t*  in_mount_handle,
                    struct statvfs** out_statvfs)
{
    if ((in_mount_handle == NULL) || (out_statvfs == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcStatVFS");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        //
        // alloc a struct to fill in and set it to be returned
        // NOTE: The caller is responsible for freeing this memory.
        *out_statvfs = statvfs_resp_to_struct(ctx, in_mount_handle);

    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}


int proxyfs_symlink(mount_handle_t* in_mount_handle,
                    uint64_t        in_inode_number,
                    char*           in_basename,
                    char*           in_target,
                    uid_t           in_uid,
                    gid_t           in_gid)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcSymlink");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[BASENAME],  in_basename);
    jsonrpc_set_req_param_str   (ctx, ptable[TARGET],    in_target);
    jsonrpc_set_req_param_int   (ctx, ptable[USERID],    in_uid);
    jsonrpc_set_req_param_int   (ctx, ptable[GROUPID],   in_gid);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_symlink_path(mount_handle_t* in_mount_handle,
                         char*           in_fullpath,
                         char*           in_target_fullpath,
                         uid_t           in_uid,
                         gid_t           in_gid)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcSymlinkPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID],     in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH],     in_fullpath);
    jsonrpc_set_req_param_str(ctx, ptable[TGT_FULLPATH], in_target_fullpath);
    jsonrpc_set_req_param_int(ctx, ptable[USERID],       in_uid);
    jsonrpc_set_req_param_int(ctx, ptable[GROUPID],      in_gid);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_async_send(proxyfs_io_request_t *req)
{
    if ((req == NULL) || (req->mount_handle == NULL)) {
        return EINVAL;
    }

    // Schedule the work and return
    return schedule_io_work(req);
}

int proxyfs_sync_io(proxyfs_io_request_t *req)
{
    // XXX TODO: make sure callback is null because we won't be calling it?
    //
    int ret = 0;

    switch (req->op) {
        case IO_READ:
            ret = proxyfs_read_req(req, io_sock_fd);
            break;
        case IO_WRITE:
            ret = proxyfs_write_req(req, io_sock_fd);
            break;
        default:
            req->error = EINVAL;
            ret = EINVAL;
            break;
    }

    return ret;
}

int proxyfs_type(mount_handle_t* in_mount_handle,
                 uint64_t        in_inode_number,
                 uint16_t*       out_file_type)
{
    if ((in_mount_handle == NULL) || (out_file_type == NULL)) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcType");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status == 0) {
        // Success; Set the values to be returned
        *out_file_type = jsonrpc_get_resp_uint64(ctx, ptable[FILE_TYPE]);
    } else {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}


int proxyfs_unlink(mount_handle_t* in_mount_handle,
                   uint64_t        in_inode_number,
                   char*           in_basename)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcUnlink");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
    jsonrpc_set_req_param_str   (ctx, ptable[BASENAME],  in_basename);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_unlink_path(mount_handle_t* in_mount_handle,
                        char*           in_fullpath)
{
    if (in_mount_handle == NULL) {
        return EINVAL;
    }

    // Get context and set the method
    jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcUnlinkPath");

    // Set the params based on what was passed in
    jsonrpc_set_req_param_str(ctx, ptable[MOUNT_ID], in_mount_handle->mount_id_as_str);
    jsonrpc_set_req_param_str(ctx, ptable[FULLPATH], in_fullpath);

    // Call RPC
    int rsp_status = jsonrpc_exec_request_blocking(ctx);
    if (rsp_status != 0) {
        handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
    }

    // Clean up jsonrpc context and return
    jsonrpc_close(ctx);
    return rsp_status;
}

int proxyfs_unmount(mount_handle_t* in_mount_handle)
{
    if (in_mount_handle != NULL) {
        pfs_rpc_close(in_mount_handle->rpc_handle); // XXX TODO: move inside proxyfs_jsonrpc.c?
        if (in_mount_handle->mount_id_as_str != NULL) {
            free(in_mount_handle->mount_id_as_str);
        }
        free(in_mount_handle);
    }
    // XXX TODO: remove this!
    dump_running_workers();
    return 0;
}

// NOTE: the proxyfs_write API is currently only called from our test code.
//       Samba vfs calls proxyfs_sync_io instead, which calls proxyfs_write_req.
//
int proxyfs_write(mount_handle_t* in_mount_handle,
                  uint64_t        in_inode_number,
                  uint64_t        in_offset,
                  uint8_t*        in_bufptr,
                  size_t          in_bufsize,
                  uint64_t*       out_size)
{
    if ((in_mount_handle == NULL) || (out_size == NULL) || (in_bufptr == NULL)) {
        return EINVAL;
    }

    if (in_bufsize == 0) {
        *out_size = 0;
        return 0;
    }

    int rsp_status = 0;

    // Start timing
    profiler_t*  profiler  = NewProfiler(WRITE);

    if (use_fastpath_for_write) {

        proxyfs_io_request_t req = {
            .op           = IO_READ,
            .mount_handle = in_mount_handle,
            .inode_number = in_inode_number,
            .offset       = in_offset,
            .length       = in_bufsize,
            .data         = in_bufptr,
            .error        = 0,
            .out_size     = 0,
            .done_cb      = NULL,
            .done_cb_arg  = NULL,
            .done_cb_fd   = 0,
        };

        dump_io_req(req, __FUNCTION__);
        DPRINTF("calling proxyfs_write_req.\n");

        // Call the write request handler
        rsp_status = proxyfs_write_req(&req, io_sock_fd);

        // Get the status and size out of the response
        //
        if (rsp_status == 0) {
            // If the request handler didn't return an error, get the status out of the request
            rsp_status = req.error;
        }
        *out_size  = req.out_size;
        DPRINTF("proxyfs_write_req returned status=%d, out_size=%ld.\n", rsp_status, *out_size);
        dump_io_req(req, __FUNCTION__);

        if (rsp_status != 0) {
            DPRINTF("status: %d\n", rsp_status);
        }

    } else {

        // Get context and set the method
        jsonrpc_context_t* ctx = jsonrpc_open(in_mount_handle->rpc_handle, "RpcWrite");
        jsonrpc_set_profiler(ctx, profiler);

        // Set the params based on what was passed in
        jsonrpc_set_req_param_str   (ctx, ptable[MOUNT_ID],  in_mount_handle->mount_id_as_str);
        jsonrpc_set_req_param_uint64(ctx, ptable[INODE_NUM], in_inode_number);
        jsonrpc_set_req_param_uint64(ctx, ptable[OFFSET],    in_offset);

        // Encode binary data into a JSON string
        //AddProfilerEvent(profiler, BEFORE_BASE64_ENCODE);
        jsonrpc_set_req_param_buf   (ctx, ptable[BUF],       in_bufptr, in_bufsize);
        AddProfilerEvent(profiler, AFTER_BASE64_ENCODE);

        // Add timestamp of when we sent the request
        struct timespec sendTimeUnix;
        clock_gettime(CLOCK_REALTIME, &sendTimeUnix);
        jsonrpc_set_req_param_int64(ctx, ptable[SEND_TIME_SEC],  sendTimeUnix.tv_sec);
        jsonrpc_set_req_param_int64(ctx, ptable[SEND_TIME_NSEC], sendTimeUnix.tv_nsec);
        AddProfilerEventTime(profiler, RPC_SEND_TIMESTAMP, sendTimeUnix);

        // Call RPC
        //AddProfilerEvent(profiler, BEFORE_RPC_CALL);
        rsp_status = jsonrpc_exec_request_blocking(ctx);
        struct timespec respTimeUnix;
        clock_gettime(CLOCK_REALTIME, &respTimeUnix);

        struct timespec rspSendTime;
        struct timespec reqRecTime;
        if (rsp_status == 0) {
            // Success; Set the values to be returned
            *out_size = jsonrpc_get_resp_uint64(ctx, ptable[SIZE]);

            rspSendTime.tv_sec  = jsonrpc_get_resp_int64(ctx, ptable[SEND_TIME_SEC]);
            rspSendTime.tv_nsec = jsonrpc_get_resp_int64(ctx, ptable[SEND_TIME_NSEC]);
            reqRecTime.tv_sec   = jsonrpc_get_resp_int64(ctx, ptable[REC_TIME_SEC]);
            reqRecTime.tv_nsec  = jsonrpc_get_resp_int64(ctx, ptable[REC_TIME_NSEC]);

            int64_t reqDelivLatencyNs =  diffNs(reqRecTime, sendTimeUnix);
            int64_t respDelivLatencyNs = diffNs(rspSendTime, respTimeUnix);

            //PRINTF("rspSendTime.tv_sec = %ld tv_nsec = %ld respDelivLatency = %ld us\n",
            //       rspSendTime.tv_sec, rspSendTime.tv_nsec, respDelivLatencyNs/1000);
            //PRINTF("reqRecTime.tv_sec = %ld tv_nsec = %ld reqDelivLatency = %ld us (%ld ns)\n",
            //       reqRecTime.tv_sec, reqRecTime.tv_nsec, reqDelivLatencyNs/1000, reqDelivLatencyNs);


            // Add timestamp for when ProxyFS sent the response.
            // We record when we received it as AFTER_RPC.
            AddProfilerEventTime(profiler, RPC_RESP_SEND_TIME, rspSendTime);

            // Now add an event for the request receive time
            AddProfilerEventTime(profiler, RPC_REQ_DELIVERY_TIME, reqRecTime);

            //PRINTF("reqDeliveryTime.tv_sec = %ld tv_nsec = %ld\n",
            //       sendTimeUnix.tv_sec, sendTimeUnix.tv_nsec);

        } else {
            handle_rsp_error(__FUNCTION__, &rsp_status, in_mount_handle);
        }
        AddProfilerEventTime(profiler, AFTER_RPC, respTimeUnix);

        // Clean up jsonrpc context and return
        jsonrpc_close(ctx);
    }

done:
    // Stop timing and print latency
    StopProfiler(profiler);
    DumpProfiler(profiler);
    DeleteProfiler(profiler);

    // Special handling for read/write/flush: translate ENOENT to EBADF
    if (rsp_status == ENOENT) {
        rsp_status = EBADF;
    }

    return rsp_status;
}

int proxyfs_write_req(proxyfs_io_request_t *req, int sock_fd)
{
    int           sock_ret;
    io_req_hdr_t  req_hdr = {
            .op_type      = 1001,
            .inode_number = req->inode_number,
            .offset       = req->offset,
            .length       = req->length,
    };
    io_resp_hdr_t resp_hdr;

    (void)memcpy(req_hdr.mount_id, req->mount_handle->mount_id_as_bytes, MOUNT_ID_SIZE);

    if ((req == NULL) || (req->mount_handle == NULL) || (req->data == NULL)) {
        return EINVAL;
    }

    if (req->length == 0) {
        req->out_size = 0;
        return 0;
    }

    profiler_t*  profiler  = NewProfiler(WRITE);

    if ( fail(WRITE_BROKEN_PIPE_FAULT) ) {
        req->error = ENODEV;
        req->out_size = 0;
        goto done;
    }

    // Send request
    sock_ret = write_to_socket(sock_fd, &req_hdr, sizeof(req_hdr));
    if (0 != sock_ret) {
        req->error = EIO;
        goto done;
    }

    // Send write data
    sock_ret = write_to_socket(sock_fd, req->data, req->length);
    if (0 != sock_ret) {
        req->error = EIO;
        goto done;
    }

    // Receive response header
    sock_ret = read_from_socket(sock_fd, &resp_hdr, sizeof(resp_hdr));
    if (0 != sock_ret) {
        int err = -sock_ret;
        if ((err == EPIPE) || (err == ENODEV) || (err = EBADF)) {
            // TBD: Build a proper error handling mechanism to retry the operation.
            PANIC("Failed to read response from proxyfsd <-> rpc client socket\n");
        }
        req->error = EIO;
        goto done;
    }

    // Set the error to return
    req->error = (int)resp_hdr.error;
    if (0 != req->error) {
        DPRINTF("rpc returned error: %d\n", req->error);
    }

    // Set bytes written size
    req->out_size = resp_hdr.io_size;

done:
    // Stop timing and print latency
    StopProfiler(profiler);
    DumpProfiler(profiler);
    DeleteProfiler(profiler);

    // Special handling for read/write/flush: translate ENOENT to EBADF
    if (req->error == ENOENT) {
        req->error = EBADF;
    }

    return 0;
}

// Flag to control debug prints. Defaulted to on for now.
int debug_flag = 0;

void proxyfs_set_verbose()
{
    debug_flag = 1;
}

void proxyfs_unset_verbose()
{
    debug_flag = 0;
}
