#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Telegram cache4 db parser, signatures file.
#
# Released under MIT License
#
# Copyright (c) 2019 Francesco "dfirfpi" Picasso, Reality Net System Solutions
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
"""Telegram blobs parsing."""

# pylint: disable=C0302,C0115,C0116,W0212,W0108,R0201,R0904

import datetime
from construct import (
    Struct,
    Computed,
    Peek,
    Byte,
    IfThenElse,
    this,
    Int32ul,
    Padding,
    If,
    Bytes,
    Hex,
    Const,
    Int64ul,
    LazyBound,
    setGlobalPrintFullStrings,
    setGlobalPrintPrivateEntries,
    Switch,
    FlagsEnum,
    Array,
    Float64b,
    GreedyBytes,
    Terminated,
    Double,
)

import logger

# ------------------------------------------------------------------------------


def decode_tstring(binarray):
    try:
        str_utf = binarray.decode("utf-8")
    except UnicodeDecodeError:
        logger.error("unable to decode string: %s", binarray)
        str_utf = binarray
    return str_utf


# ------------------------------------------------------------------------------


class tblob:  # pylint: disable=C0103

    # --------------------------------------------------------------------------

    tstring_struct = Struct(
        "_sname" / Computed("tstring"),
        "_check" / Peek(Byte),
        "_pl" / IfThenElse(this._check >= 254, Int32ul, Byte),
        "_len"
        / IfThenElse(this._check >= 254, Computed(this._pl >> 8), Computed(this._pl)),
        # 'value' / PaddedString(this._len, 'utf-8'),
        "_value" / Bytes(this._len),
        "string" / Computed(lambda x: decode_tstring(x._value)),
        IfThenElse(
            this._check >= 254,
            If(this._len % 4, Padding(4 - this._len % 4)),
            If((this._len + 1) % 4, Padding(4 - (this._len + 1) % 4)),
        ),
    )

    tbytes_struct = Struct(
        "_sname" / Computed("tbytes"),
        "_check" / Peek(Byte),
        "_pl" / IfThenElse(this._check >= 254, Int32ul, Byte),
        "len"
        / IfThenElse(this._check >= 254, Computed(this._pl >> 8), Computed(this._pl)),
        # 'bytes' / Array(this.len, Byte),
        "bytes" / Hex(Bytes(this.len)),
        IfThenElse(
            this._check >= 254,
            If(this.len % 4, Padding(4 - this.len % 4)),
            If((this.len + 1) % 4, Padding(4 - (this.len + 1) % 4)),
        ),
    )

    tbool_struct = Struct(
        "sname" / Computed("boolean"),
        "_signature" / Int32ul,
        "value"
        / IfThenElse(
            this._signature == 0xBC799737,
            Computed("false"),
            IfThenElse(
                this._signature == 0x997275B5, Computed("true"), Computed("ERROR")
            ),
        ),
    )

    # This is not struct define by Telegram, but it's useful to get human
    # readable timestamps.
    ttimestamp_struct = Struct(
        "epoch" / Int32ul,
        "date"
        / Computed(
            lambda this: datetime.datetime.utcfromtimestamp(this.epoch).isoformat()
        ),
    )

    # --------------------------------------------------------------------------

    def __init__(self):
        setGlobalPrintFullStrings(True)
        setGlobalPrintPrivateEntries(False)
        self._callbacks = {}
        logger.debug("building callbacks ...")
        for signature, blob_tuple in tblob.tdss_callbacks.items():
            logger.debug("adding callback %s (%s)", hex(signature), blob_tuple[1])
            self._callbacks[signature] = blob_tuple
        logger.debug("building callbacks ended")

    # --------------------------------------------------------------------------

    @property
    def callbacks(self):
        assert self._callbacks
        return self._callbacks

    # --------------------------------------------------------------------------

    def parse_blob(self, data):
        pblob = None
        signature = int.from_bytes(data[:4], "little")
        if signature in self.callbacks:
            blob_parser, name, beautify = self.callbacks[signature]
            if blob_parser:
                pblob = blob_parser(self).parse(data)
                # Some structures has the 'UNPARSED' field to get the remaining
                # bytes. It's expected to get some of these cases (e.g. wrong
                # flags, it happens...) and I want everything to be in front of
                # the analyst. So, if UNPARSED has a length > 0, a warning
                # message is raised, but the missing data is in the blob.
                unparsed = getattr(pblob, "UNPARSED", None)
                if unparsed:
                    unparsed_len = len(pblob.UNPARSED)
                    if unparsed_len:
                        logger.warning(
                            "Object: %s [0x%x] contains unparsed "
                            "data [%d bytes], see UNPARSED field",
                            name,
                            signature,
                            unparsed_len,
                        )
                data_len = len(data)
                # In case the object has not (yet) the UNPARSED field, the next
                # check will raise and error and report the missed data. Note
                # that the missed data will be not reported in the blob.
                object_len = pblob._io.tell()
                if data_len != object_len:
                    logger.error(
                        "Not all data parsed for object: %s [0x%x], "
                        "input: %d, parsed: %d, missed: %s",
                        name,
                        signature,
                        data_len,
                        object_len,
                        data[object_len:],
                    )
                if beautify:
                    pass  # [TBR] Actually not implemented.
            else:
                logger.warning("blob '%s' [%s] not supported", name, hex(signature))
        else:
            logger.error("unknown signature %s", hex(signature))
        return pblob

    # --------------------------------------------------------------------------
    # TDSs implementation
    # --------------------------------------------------------------------------

    def audio_old2_struct(self):
        return Struct(
            "sname" / Computed("audio_old2"),
            "signature" / Hex(Const(0xC7AC6496, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "duration" / Int32ul,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "dc_id" / Int32ul,
        )

    def audio_layer45_struct(self):
        return Struct(
            "sname" / Computed("audio_layer45"),
            "signature" / Hex(Const(0xF9E35055, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "duration" / Int32ul,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "dc_id" / Int32ul,
        )

    def audio_old_struct(self):
        return Struct(
            "sname" / Computed("audio_old"),
            "signature" / Hex(Const(0x427425E7, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "duration" / Int32ul,
            "size" / Int32ul,
            "dc_id" / Int32ul,
        )

    def audio_encrypted_struct(self):
        return Struct(
            "sname" / Computed("audio_encrypted"),
            "signature" / Hex(Const(0x555555F6, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "duration" / Int32ul,
            "size" / Int32ul,
            "dc_id" / Int32ul,
            "key" / self.tbytes_struct,
            "iv" / self.tbytes_struct,
        )

    def audio_empty_layer45_struct(self):
        return Struct(
            "sname" / Computed("audio_empty_layer45"),
            "signature" / Hex(Const(0x586988D8, Int32ul)),
            "id" / Int64ul,
        )

    def audio_structures(self, name):
        tag_map = {
            0xC7AC6496: LazyBound(lambda: self.audio_old2_struct()),
            0xF9E35055: LazyBound(lambda: self.audio_layer45_struct()),
            0x427425E7: LazyBound(lambda: self.audio_old_struct()),
            0x555555F6: LazyBound(lambda: self.audio_encrypted_struct()),
            0x586988D8: LazyBound(lambda: self.audio_empty_layer45_struct()),
        }
        return "audio_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def bot_command_struct(self):
        return Struct(
            "sname" / Computed("bot_command"),
            "signature" / Hex(Const(0xC27AC8C7, Int32ul)),
            "command" / self.tstring_struct,
            "description" / self.tstring_struct,
        )

    # --------------------------------------------------------------------------

    def base_theme_night_struct(self):
        return Struct(
            "sname" / Computed("base_theme_night"),
            "signature" / Hex(Const(0xB7B31EA8, Int32ul)),
        )

    def base_theme_classic_struct(self):
        return Struct(
            "sname" / Computed("base_theme_classic"),
            "signature" / Hex(Const(0xC3A12462, Int32ul)),
        )

    def base_theme_day_struct(self):
        return Struct(
            "sname" / Computed("base_theme_day"),
            "signature" / Hex(Const(0xFBD81688, Int32ul)),
        )

    def base_theme_arctic_struct(self):
        return Struct(
            "sname" / Computed("base_theme_arctic"),
            "signature" / Hex(Const(0x5B11125A, Int32ul)),
        )

    def base_theme_tinted_struct(self):
        return Struct(
            "sname" / Computed("base_theme_tinted"),
            "signature" / Hex(Const(0x6D5F77EE, Int32ul)),
        )

    def base_theme_structures(self, name):
        tag_map = {
            0xB7B31EA8: LazyBound(lambda: self.base_theme_night_struct()),
            0xC3A12462: LazyBound(lambda: self.base_theme_classic_struct()),
            0xFBD81688: LazyBound(lambda: self.base_theme_day_struct()),
            0x5B11125A: LazyBound(lambda: self.base_theme_arctic_struct()),
            0x6D5F77EE: LazyBound(lambda: self.base_theme_tinted_struct()),
        }
        return "base_theme_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def bot_info_struct(self):
        return Struct(
            "sname" / Computed("bot_info"),
            "signature" / Hex(Const(0x98E81D3A, Int32ul)),
            "user_id" / Int32ul,
            "description" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "bot_commands_num" / Int32ul,
            "bot_commands_array"
            / Array(this.bot_commands_num, self.bot_command_struct()),
        )

    def bot_info_layer48_struct(self):
        return Struct(
            "sname" / Computed("bot_info_layer48"),
            "signature" / Hex(Const(0x09CF585D, Int32ul)),
            "user_id" / Int32ul,
            "version" / Int32ul,
            "unknown" / self.tstring_struct,
            "description" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "bot_commands_num" / Int32ul,
            "bot_commands_array"
            / Array(this.bot_commands_num, self.bot_command_struct()),
        )

    def bot_info_empty_layer48_struct(self):
        return Struct(
            "sname" / Computed("bot_info_empty_layer48"),
            "signature" / Hex(Const(0xBB2E37CE, Int32ul)),
        )

    def bot_info_structures(self, name):
        tag_map = {
            0x98E81D3A: LazyBound(lambda: self.bot_info_struct()),
            0xBB2E37CE: LazyBound(lambda: self.bot_info_empty_layer48_struct()),
            0x09CF585D: LazyBound(lambda: self.bot_info_layer48_struct()),
        }
        return "bot_info_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def channel_admin_rights_layer92_struct(self):
        return Struct(
            "sname" / Computed("channel_admin_rights_layer92"),
            "signature" / Hex(Const(0x5D7CEBA5, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                change_info=1,
                post_messages=2,
                edit_messages=4,
                delete_messages=8,
                ban_users=16,
                invite_users=32,
                pin_messages=128,
                add_admins=512,
                manage_call=1024,
            ),
        )

    def channel_banned_rights_layer92_struct(self):
        return Struct(
            "sname" / Computed("channel_banned_rights_layer92"),
            "signature" / Hex(Const(0x58CF4249, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                view_messages=1,
                send_messages=2,
                send_media=4,
                send_stickers=8,
                send_gifs=16,
                send_games=32,
                send_inline=64,
                embed_links=128,
            ),
            "until_timestamp" / Int32ul,
        )

    def chat_admin_rights_struct(self):
        return Struct(
            "sname" / Computed("chat_admin_rights"),
            "signature" / Hex(Const(0x5FB224D5, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                change_info=1,
                post_messages=2,
                edit_messages=4,
                delete_messages=8,
                ban_users=16,
                invite_users=32,
                pin_messages=128,
                add_admins=512,
            ),
        )

    def chat_banned_rights_struct(self):
        return Struct(
            "sname" / Computed("chat_banned_rights"),
            "signature" / Hex(Const(0x9F120418, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                view_messages=1,
                send_messages=2,
                send_media=4,
                send_stickers=8,
                send_gifs=16,
                send_games=32,
                send_inline=64,
                embed_links=128,
                send_polls=256,
                change_info=1024,
                invite_users=32768,
                pin_messages=131072,
            ),
            "until_timestamp" / Int32ul,
        )

    # --------------------------------------------------------------------------

    def chat_empty_struct(self):
        return Struct(
            "sname" / Computed("chat_empty"),
            "signature" / Hex(Const(0x9BA2D800, Int32ul)),
            "id" / Int32ul,
            "title" / Computed("DELETED"),
        )

    def channel_forbidden_struct(self):
        return Struct(
            "sname" / Computed("channel_forbidden"),
            "signature" / Hex(Const(0x289DA732, Int32ul)),
            "flags"
            / FlagsEnum(Int32ul, broadcast=32, megagroup=256, has_expiration=65536),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "title" / self.tstring_struct,
            "util_timestamp" / If(this.flags.has_expiration, Int32ul),
        )

    def channel_forbidden_layer52_struct(self):
        return Struct(
            "sname" / Computed("channel_forbidden_layer52"),
            "signature" / Hex(Const(0x2D85832C, Int32ul)),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "title" / self.tstring_struct,
        )

    def channel_forbidden_layer67_struct(self):
        return Struct(
            "sname" / Computed("channel_forbidden_layer67"),
            "signature" / Hex(Const(0x8537784F, Int32ul)),
            "flags" / FlagsEnum(Int32ul, broadcast=32, megagroup=256),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "title" / self.tstring_struct,
        )

    def channel_layer104_struct(self):
        return Struct(
            "sname" / Computed("channel_layer104"),
            "signature" / Hex(Const(0x4DF30834, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                left=4,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                restricted=512,
                signatures=2048,
                is_min=4096,
                has_admin_rights=16384,
                has_banned_rights=32768,
                has_participant_count=131072,
                has_access_hash=8192,
                scam=524288,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "photo" / self.chat_photo_structures("photo"),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "restrict_reason" / If(this.flags.restricted, self.tstring_struct),
            "admin_rights"
            / If(this.flags.has_admin_rights, self.chat_admin_rights_struct()),
            "banned_rights"
            / If(this.flags.has_banned_rights, self.chat_banned_rights_struct()),
            "participants_count" / If(this.flags.has_participant_count, Int32ul),
        )

    def channel_old_struct(self):
        return Struct(
            "sname" / Computed("channel_old"),
            "signature" / Hex(Const(0x678E9587, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                kicked=2,
                left=4,
                moderator=16,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                explicit_content=512,
            ),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "photo" / self.chat_photo_structures("photo"),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
        )

    def channel_layer48_struct(self):
        return Struct(
            "sname" / Computed("channel_layer48"),
            "signature" / Hex(Const(0x4B1B7506, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                kicked=2,
                left=4,
                moderator=16,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                restricted=512,
                signatures=2048,
                is_min=4096,
                has_access_hash=8192,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "photo" / self.chat_photo_structures("photo"),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "restrict_reason" / If(this.flags.restricted, self.tstring_struct),
        )

    def channel_layer67_struct(self):
        return Struct(
            "sname" / Computed("channel_layer67"),
            "signature" / Hex(Const(0xA14DCA52, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                kicked=2,
                left=4,
                moderator=16,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                restricted=512,
                signatures=2048,
                is_min=4096,
                has_access_hash=8192,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "photo" / self.chat_photo_structures("photo"),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "restrict_reason" / If(this.flags.restricted, self.tstring_struct),
        )

    def channel_layer72_struct(self):
        return Struct(
            "sname" / Computed("channel_layer72"),
            "signature" / Hex(Const(0x0CB44B1C, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                left=4,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                restricted=512,
                signatures=2048,
                is_min=4096,
                has_admin_rights=16384,
                has_banned_rights=32768,
                has_access_hash=8192,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "restrict_reason" / If(this.flags.restricted, self.tstring_struct),
            "admin_rights"
            / If(
                this.flags.has_admin_rights, self.channel_admin_rights_layer92_struct()
            ),
            "banned_rights"
            / If(
                this.flags.has_banned_rights,
                self.channel_banned_rights_layer92_struct(),
            ),
        )

    def channel_layer77_struct(self):
        return Struct(
            "sname" / Computed("channel_layer77"),
            "signature" / Hex(Const(0x450B7115, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                left=4,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                restricted=512,
                signatures=2048,
                is_min=4096,
                has_admin_rights=16384,
                has_banned_rights=32768,
                has_participant_count=131072,
                has_access_hash=8192,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "photo" / self.chat_photo_structures("photo"),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "restrict_reason" / If(this.flags.restricted, self.tstring_struct),
            "admin_rights"
            / If(
                this.flags.has_admin_rights, self.channel_admin_rights_layer92_struct()
            ),
            "banned_rights"
            / If(
                this.flags.has_banned_rights,
                self.channel_banned_rights_layer92_struct(),
            ),
            "participants_count" / If(this.flags.has_participant_count, Int32ul),
        )

    def channel_layer92_struct(self):
        return Struct(
            "sname" / Computed("channel_layer92"),
            "signature" / Hex(Const(0xC88974AC, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                left=4,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                restricted=512,
                signatures=2048,
                is_min=4096,
                has_admin_rights=16384,
                has_banned_rights=32768,
                has_participant_count=131072,
                has_access_hash=8192,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "photo" / self.chat_photo_structures("photo"),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "restrict_reason" / If(this.flags.restricted, self.tstring_struct),
            "admin_rights"
            / If(
                this.flags.has_admin_rights, self.channel_admin_rights_layer92_struct()
            ),
            "banned_rights"
            / If(
                this.flags.has_banned_rights,
                self.channel_banned_rights_layer92_struct(),
            ),
            "participants_count" / If(this.flags.has_participant_count, Int32ul),
        )

    def channel_struct(self):
        return Struct(
            "sname" / Computed("channel"),
            "signature" / Hex(Const(0xD31A961E, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                left=4,
                broadcast=32,
                has_username=64,
                verified=128,
                megagroup=256,
                restricted=512,
                signatures=2048,
                is_min=4096,
                has_access_hash=8192,
                has_admin_rights=16384,
                has_banned_rights=32768,
                has_participant_count=131072,
                is_scam=524288,
                has_link=1048576,
                has_geo=2097152,
                is_slowmode_enabled=4194304,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "title" / self.tstring_struct,
            "username" / If(this.flags.has_username, self.tstring_struct),
            "photo" / self.chat_photo_structures("photo"),
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "restrict_reasons"
            / If(
                this.flags.restricted,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "restrict_reasons_num" / Int32ul,
                    "restrict_reasons_array"
                    / Array(
                        this.restrict_reasons_num, self.restriction_reason_struct()
                    ),
                ),
            ),
            "admin_rights"
            / If(this.flags.has_admin_rights, self.chat_admin_rights_struct()),
            "banned_rights"
            / If(this.flags.has_banned_rights, self.chat_banned_rights_struct()),
            "participants_count" / If(this.flags.has_participant_count, Int32ul),
        )

    def chat_struct(self):
        return Struct(
            "sname" / Computed("chat"),
            "signature" / Hex(Const(0x3BDA1BDE, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                creator=1,
                kicked=2,
                left=4,
                deactivated=32,
                is_migrated=64,
                has_admin_rights=16384,
                has_banned_rights=262144,
            ),
            "id" / Int32ul,
            "title" / self.tstring_struct,
            "photo" / self.chat_photo_structures("photo"),
            "participants_count" / Int32ul,
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "migrated_to"
            / If(this.flags.is_migrated, self.input_channel_structures("migrated_to")),
            "admin_rights"
            / If(this.flags.has_admin_rights, self.chat_admin_rights_struct()),
            "banned_rights"
            / If(this.flags.has_banned_rights, self.chat_banned_rights_struct()),
        )

    def chat_old_struct(self):
        return Struct(
            "sname" / Computed("chat_old"),
            "signature" / Hex(Const(0x6E9C9BC7, Int32ul)),
            "id" / Int32ul,
            "title" / self.tstring_struct,
            "photo" / self.chat_photo_structures("photo"),
            "participants_count" / Int32ul,
            "date" / self.ttimestamp_struct,
            "left" / self.tbool_struct,
            "version" / Int32ul,
        )

    def chat_old2_struct(self):
        return Struct(
            "sname" / Computed("chat_old2"),
            "signature" / Hex(Const(0x7312BC48, Int32ul)),
            "flags" / FlagsEnum(Int32ul, creator=1, kicked=2, left=4, deactivated=32),
            "id" / Int32ul,
            "title" / self.tstring_struct,
            "photo" / self.chat_photo_structures("photo"),
            "participants_count" / Int32ul,
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
        )

    def chat_forbidden_struct(self):
        return Struct(
            "sname" / Computed("chat_forbidden"),
            "signature" / Hex(Const(0x07328BDB, Int32ul)),
            "id" / Int32ul,
            "title" / self.tstring_struct,
        )

    def chat_forbidden_old_struct(self):
        return Struct(
            "sname" / Computed("chat_forbidden_old"),
            "signature" / Hex(Const(0xFB0CCC41, Int32ul)),
            "id" / Int32ul,
            "title" / self.tstring_struct,
            "date" / Int32ul,
        )

    def chat_layer92_struct(self):
        return Struct(
            "sname" / Computed("chat_layer92"),
            "signature" / Hex(Const(0xD91CDD54, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul, creator=1, kicked=2, left=4, deactivated=32, is_migrated=64
            ),
            "id" / Int32ul,
            "title" / self.tstring_struct,
            "photo" / self.chat_photo_structures("photo"),
            "participants_count" / Int32ul,
            "date" / self.ttimestamp_struct,
            "version" / Int32ul,
            "migrated_to"
            / If(this.flags.is_migrated, self.input_channel_structures("migrated_to")),
        )

    def chat_structures(self, name):
        tag_map = {
            0xD31A961E: LazyBound(lambda: self.channel_struct()),
            0x8537784F: LazyBound(lambda: self.channel_forbidden_layer67_struct()),
            0x9BA2D800: LazyBound(lambda: self.chat_empty_struct()),
            0xA14DCA52: LazyBound(lambda: self.channel_layer67_struct()),
            0xC88974AC: LazyBound(lambda: self.channel_layer92_struct()),
            0xD91CDD54: LazyBound(lambda: self.chat_layer92_struct()),
            0xFB0CCC41: LazyBound(lambda: self.chat_forbidden_old_struct()),
            0x07328BDB: LazyBound(lambda: self.chat_forbidden_struct()),
            0x0CB44B1C: LazyBound(lambda: self.channel_layer72_struct()),
            0x289DA732: LazyBound(lambda: self.channel_forbidden_struct()),
            0x2D85832C: LazyBound(lambda: self.channel_forbidden_layer52_struct()),
            0x3BDA1BDE: LazyBound(lambda: self.chat_struct()),
            0x450B7115: LazyBound(lambda: self.channel_layer77_struct()),
            0x4B1B7506: LazyBound(lambda: self.channel_layer48_struct()),
            0x4DF30834: LazyBound(lambda: self.channel_layer104_struct()),
            0x678E9587: LazyBound(lambda: self.channel_old_struct()),
            0x6E9C9BC7: LazyBound(lambda: self.chat_old_struct()),
            0x7312BC48: LazyBound(lambda: self.chat_old2_struct()),
        }
        return "chat_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def chat_photo_layer115_struct(self):
        return Struct(
            "sname" / Computed("chat_photo_layer115"),
            "signature" / Hex(Const(0x475CDBD5, Int32ul)),
            "photo_small" / self.file_location_structures("photo_small"),
            "photo_big" / self.file_location_structures("photo_big"),
            "dc_id" / Int32ul,
        )

    def chat_photo_empty_struct(self):
        return Struct(
            "sname" / Computed("chat_photo_empty"),
            "signature" / Hex(Const(0x37C1011C, Int32ul)),
        )

    def chat_photo_layer97_struct(self):
        return Struct(
            "sname" / Computed("chat_photo_layer97"),
            "signature" / Hex(Const(0x6153276A, Int32ul)),
            "photo_small" / self.file_location_structures("photo_small"),
            "photo_big" / self.file_location_structures("photo_big"),
        )

    def chat_photo_struct(self):
        return Struct(
            "sname" / Computed("chat_photo"),
            "signature" / Hex(Const(0xD20B9F3C, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_video=1,
            ),
            "photo_small" / self.file_location_structures("photo_small"),
            "photo_big" / self.file_location_structures("photo_big"),
            "dc_id" / Int32ul,
        )

    def chat_photo_structures(self, name):
        tag_map = {
            0x37C1011C: LazyBound(lambda: self.chat_photo_empty_struct()),
            0x6153276A: LazyBound(lambda: self.chat_photo_layer97_struct()),
            0x475CDBD5: LazyBound(lambda: self.chat_photo_layer115_struct()),
            0xD20B9F3C: LazyBound(lambda: self.chat_photo_struct()),
        }
        return "chat_photo_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def contact_link_contact_struct(self):
        return Struct(
            "sname" / Computed("contact_link_contact"),
            "signature" / Hex(Const(0xD502C2D0, Int32ul)),
        )

    def contact_link_none_struct(self):
        return Struct(
            "sname" / Computed("contact_link_none"),
            "signature" / Hex(Const(0xFEEDD3AD, Int32ul)),
        )

    def contact_link_has_phone_struct(self):
        return Struct(
            "sname" / Computed("contact_link_has_phone"),
            "signature" / Hex(Const(0x268F3F59, Int32ul)),
        )

    def contact_link_unknown_struct(self):
        return Struct(
            "sname" / Computed("contact_link_unknown"),
            "signature" / Hex(Const(0x5F4F9247, Int32ul)),
        )

    def contact_link_structures(self, name):
        tag_map = {
            0xD502C2D0: LazyBound(lambda: self.contact_link_contact_struct()),
            0xFEEDD3AD: LazyBound(lambda: self.contact_link_none_struct()),
            0x268F3F59: LazyBound(lambda: self.contact_link_has_phone_struct()),
            0x5F4F9247: LazyBound(lambda: self.contact_link_unknown_struct()),
        }
        return "contact_link_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    def contacts_link_layer101_struct(self):
        return Struct(
            "sname" / Computed("contacts_link_layer101"),
            "signature" / Hex(Const(0x3ACE484C, Int32ul)),
            "my_link" / self.contact_link_structures("my_link"),
            "foreign_link" / self.contact_link_structures("foreign_link"),
            "user" / self.user_structures("user"),
        )

    # --------------------------------------------------------------------------

    def decrypted_message_action_set_message_ttl_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_set_message_ttl"),
            "signature" / Hex(Const(0xA1733AEC, Int32ul)),
            "ttl_seconds" / Int32ul,
        )

    def decrypted_message_action_screenshot_messages_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_screenshot_messages"),
            "signature" / Hex(Const(0x8AC1F475, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "random_ids_num" / Int32ul,
            "random_ids_array" / Array(this.random_ids_num, Int64ul),
        )

    def decrypted_message_action_noop_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_noop"),
            "signature" / Hex(Const(0xA82FDD63, Int32ul)),
        )

    def decrypted_message_action_typing_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_typing"),
            "signature" / Hex(Const(0xCCB27641, Int32ul)),
            "action" / self.send_message_action_structures("action"),
        )

    def decrypted_message_action_abort_key_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_abort_key"),
            "signature" / Hex(Const(0xDD05EC6B, Int32ul)),
            "exchange_id" / Int64ul,
        )

    def decrypted_message_action_commit_key_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_commit_key"),
            "signature" / Hex(Const(0xEC2E0B9B, Int32ul)),
            "exchange_id" / Int64ul,
            "key_fingerprint" / Int64ul,
        )

    def decrypted_message_action_notify_layer_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_notify_layer"),
            "signature" / Hex(Const(0xF3048883, Int32ul)),
            "layer" / Int32ul,
        )

    def decrypted_message_action_request_key_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_request_key"),
            "signature" / Hex(Const(0xF3C9611B, Int32ul)),
            "exchange_id" / Int64ul,
            "g_a" / self.tbytes_struct,
        )

    def decrypted_message_action_read_messages_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_read_messages"),
            "signature" / Hex(Const(0x0C4F40BE, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "random_ids_num" / Int32ul,
            "random_ids_array" / Array(this.random_ids_num, Int64ul),
        )

    def decrypted_message_action_resend_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_resend"),
            "signature" / Hex(Const(0x511110B0, Int32ul)),
            "start_seq_no" / Int32ul,
            "end_seq_no" / Int32ul,
        )

    def decrypted_message_action_delete_messages_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_delete_messages"),
            "signature" / Hex(Const(0x65614304, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "random_ids_num" / Int32ul,
            "random_ids_array" / Array(this.random_ids_num, Int64ul),
        )

    def decrypted_message_action_flush_history_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_flush_history"),
            "signature" / Hex(Const(0x6719E45C, Int32ul)),
        )

    def decrypted_message_action_accept_key_struct(self):
        return Struct(
            "sname" / Computed("decrypted_message_action_accept_key"),
            "signature" / Hex(Const(0x6FE1735B, Int32ul)),
            "exchange_id" / Int64ul,
            "g_b" / self.tbytes_struct,
            "key_fingerprint" / Int64ul,
        )

    def decrypted_message_action_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x8AC1F475: LazyBound(
                lambda: self.decrypted_message_action_screenshot_messages_struct()
            ),
            0xA82FDD63: LazyBound(lambda: self.decrypted_message_action_noop_struct()),
            0xCCB27641: LazyBound(
                lambda: self.decrypted_message_action_typing_struct()
            ),
            0xDD05EC6B: LazyBound(
                lambda: self.decrypted_message_action_abort_key_struct()
            ),
            0xEC2E0B9B: LazyBound(
                lambda: self.decrypted_message_action_commit_key_struct()
            ),
            0xF3048883: LazyBound(
                lambda: self.decrypted_message_action_notify_layer_struct()
            ),
            0xF3C9611B: LazyBound(
                lambda: self.decrypted_message_action_request_key_struct()
            ),
            0x0C4F40BE: LazyBound(
                lambda: self.decrypted_message_action_read_messages_struct()
            ),
            0x511110B0: LazyBound(
                lambda: self.decrypted_message_action_resend_struct()
            ),
            0x65614304: LazyBound(
                lambda: self.decrypted_message_action_delete_messages_struct()
            ),
            0x6719E45C: LazyBound(
                lambda: self.decrypted_message_action_flush_history_struct()
            ),
            0x6FE1735B: LazyBound(
                lambda: self.decrypted_message_action_accept_key_struct()
            ),
            0xA1733AEC: LazyBound(
                lambda: self.decrypted_message_action_set_message_ttl_struct()
            ),
        }
        return "decrypted_message_action_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def document_attribute_has_stickers_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_has_stickers"),
            "signature" / Hex(Const(0x9801D2F7, Int32ul)),
        )

    def document_attribute_sticker_old_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_sticker_old"),
            "signature" / Hex(Const(0xFB0A5727, Int32ul)),
            "alt" / self.tstring_struct,
        )

    def document_attribute_sticker_old2_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_sticker_old2"),
            "signature" / Hex(Const(0x994C9882, Int32ul)),
            "alt" / self.tstring_struct,
        )

    def document_attribute_audio_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_audio"),
            "signature" / Hex(Const(0x9852F9C6, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul, has_title=1, has_performer=2, has_waveform=4, is_voice=1024
            ),
            "duration" / Int32ul,
            "title" / If(this.flags.has_title, self.tstring_struct),
            "performer" / If(this.flags.has_performer, self.tstring_struct),
            "waveform" / If(this.flags.has_waveform, self.tbytes_struct),
        )

    def document_attribute_audio_layer45_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_audio_layer45"),
            "signature" / Hex(Const(0xDED218E0, Int32ul)),
            "duration" / Int32ul,
            "title" / self.tstring_struct,
            "performer" / self.tstring_struct,
        )

    def document_attribute_audio_old_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_audio_old"),
            "signature" / Hex(Const(0x051448E5, Int32ul)),
            "duration" / Int32ul,
        )

    def document_attribute_video_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_video"),
            "signature" / Hex(Const(0x0EF02CE6, Int32ul)),
            "flags" / FlagsEnum(Int32ul, round_message=1, supports_streaming=2),
            "duration" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def document_attribute_animated_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_animated"),
            "signature" / Hex(Const(0x11B58939, Int32ul)),
        )

    def document_attribute_filename_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_filename"),
            "signature" / Hex(Const(0x15590068, Int32ul)),
            "file_name" / self.tstring_struct,
        )

    def document_attribute_sticker_layer55_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_sticker_layer55"),
            "signature" / Hex(Const(0x3A556302, Int32ul)),
            "alt" / self.tstring_struct,
            "sticker_set" / self.input_sticker_set_structures("sticker_set"),
        )

    def document_attribute_video_layer65_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_video_layer65"),
            "signature" / Hex(Const(0x5910CCCB, Int32ul)),
            "duration" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def document_attribute_sticker_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_sticker"),
            "signature" / Hex(Const(0x6319D612, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_mask_coords=1, mask=2),
            "alt" / self.tstring_struct,
            "sticker_set" / self.input_sticker_set_structures("sticker_set"),
            "mask_coords" / If(this.flags.has_mask_coords, self.mask_coords_struct()),
        )

    def document_attribute_image_size_struct(self):
        return Struct(
            "sname" / Computed("document_attribute_image_size"),
            "signature" / Hex(Const(0x6C37C15C, Int32ul)),
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def document_attribute_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x9801D2F7: LazyBound(
                lambda: self.document_attribute_has_stickers_struct()
            ),
            0x9852F9C6: LazyBound(lambda: self.document_attribute_audio_struct()),
            0x994C9882: LazyBound(
                lambda: self.document_attribute_sticker_old2_struct()
            ),
            0xDED218E0: LazyBound(
                lambda: self.document_attribute_audio_layer45_struct()
            ),
            0xFB0A5727: LazyBound(lambda: self.document_attribute_sticker_old_struct()),
            0x051448E5: LazyBound(lambda: self.document_attribute_audio_old_struct()),
            0x0EF02CE6: LazyBound(lambda: self.document_attribute_video_struct()),
            0x11B58939: LazyBound(lambda: self.document_attribute_animated_struct()),
            0x15590068: LazyBound(lambda: self.document_attribute_filename_struct()),
            0x3A556302: LazyBound(
                lambda: self.document_attribute_sticker_layer55_struct()
            ),
            0x5910CCCB: LazyBound(
                lambda: self.document_attribute_video_layer65_struct()
            ),
            0x6319D612: LazyBound(lambda: self.document_attribute_sticker_struct()),
            0x6C37C15C: LazyBound(lambda: self.document_attribute_image_size_struct()),
        }
        return "document_attribute_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def document_empty_struct(self):
        return Struct(
            "sname" / Computed("document_empty"),
            "signature" / Hex(Const(0x36F8C871, Int32ul)),
            "id" / Int64ul,
        )

    def document_layer82_struct(self):
        return Struct(
            "sname" / Computed("document_layer82"),
            "signature" / Hex(Const(0x87232BC7, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "_pad" / Int32ul,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes_array"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document"),
            ),
        )

    def document_layer113_struct(self):
        return Struct(
            "sname" / Computed("document_layer113"),
            "signature" / Hex(Const(0x9BA29CC1, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_photo_size=1, mask=2),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "file_reference" / self.tbytes_struct,
            "date" / self.ttimestamp_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "photo_size"
            / If(
                this.flags.has_photo_size,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "photo_sizes_num" / Int32ul,
                    "photo_sizes_array"
                    / Array(this.photo_sizes_num, self.photo_size_structures("photo")),
                ),
            ),
            "dc_id" / Int32ul,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes_array"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document"),
            ),
        )

    def document_old_struct(self):
        return Struct(
            "sname" / Computed("document_old"),
            "signature" / Hex(Const(0x9EFC6326, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "file_name" / self.tstring_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
        )

    def document_layer53_struct(self):
        return Struct(
            "sname" / Computed("document_layer53"),
            "signature" / Hex(Const(0xF9A39F4F, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes_array"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document"),
            ),
        )

    def document_encrypted_old_struct(self):
        return Struct(
            "sname" / Computed("document_encrypted_old"),
            "signature" / Hex(Const(0x55555556, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "file_name" / self.tstring_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "key" / self.tbytes_struct,
            "iv" / self.tbytes_struct,
        )

    def document_encrypted_struct(self):
        return Struct(
            "sname" / Computed("document_encrypted"),
            "signature" / Hex(Const(0x55555558, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes_array"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document"),
            ),
            "key" / self.tbytes_struct,
            "iv" / self.tbytes_struct,
        )

    def document_layer92_struct(self):
        return Struct(
            "sname" / Computed("document_layer92"),
            "signature" / Hex(Const(0x59534E4C, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "file_reference" / self.tbytes_struct,
            "date" / self.ttimestamp_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes_array"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document"),
            ),
        )

    def document_struct(self):
        return Struct(
            "sname" / Computed("document"),
            "signature" / Hex(Const(0x1E87342B, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_photo_size=1, has_video_size=2),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "file_reference" / self.tbytes_struct,
            "date" / self.ttimestamp_struct,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "photo_size"
            / If(
                this.flags.has_photo_size,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "photo_sizes_num" / Int32ul,
                    "photo_sizes_array"
                    / Array(
                        this.photo_sizes_num, self.photo_size_structures("photo_size")
                    ),
                ),
            ),
            "video_size"
            / If(
                this.flags.has_video_size,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "video_sizes_num" / Int32ul,
                    "video_sizes_array"
                    / Array(
                        this.video_sizes_num, self.video_size_structures("video_size")
                    ),
                ),
            ),
            "dc_id" / Int32ul,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes_array"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document"),
            ),
        )

    def document_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x1E87342B: LazyBound(lambda: self.document_struct()),
            0x87232BC7: LazyBound(lambda: self.document_layer82_struct()),
            0x9BA29CC1: LazyBound(lambda: self.document_layer113_struct()),
            0x9EFC6326: LazyBound(lambda: self.document_old_struct()),
            0xF9A39F4F: LazyBound(lambda: self.document_layer53_struct()),
            0x36F8C871: LazyBound(lambda: self.document_empty_struct()),
            0x55555556: LazyBound(lambda: self.document_encrypted_old_struct()),
            0x55555558: LazyBound(lambda: self.document_encrypted_struct()),
            0x59534E4C: LazyBound(lambda: self.document_layer92_struct()),
        }
        return "document_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def encrypted_chat_empty_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat_empty"),
            "signature" / Hex(Const(0xAB7EC0A0, Int32ul)),
            "id" / Int32ul,
        )

    def encrypted_chat_requested_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat_requested"),
            "signature" / Hex(Const(0x62718A82, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_folder_is=1),
            "folder_id" / If(this.flags.has_folder_id, Int32ul),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "admin_id" / Int32ul,
            "participant_id" / Int32ul,
            "g_a" / self.tbytes_struct,
        )

    def encrypted_chat_requested_layer115_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat_requested_layer115"),
            "signature" / Hex(Const(0xC878527E, Int32ul)),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "admin_id" / Int32ul,
            "participant_id" / Int32ul,
            "g_a" / self.tbytes_struct,
        )

    def encrypted_chat_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat"),
            "signature" / Hex(Const(0xFA56CE36, Int32ul)),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "admin_id" / Int32ul,
            "participant_id" / Int32ul,
            "g_a_or_b" / self.tbytes_struct,
            "key_fingerprint" / Int64ul,
        )

    def encrypted_chat_requested_old_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat_requested_old"),
            "signature" / Hex(Const(0xFDA9A7B7, Int32ul)),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "admin_id" / Int32ul,
            "participant_id" / Int32ul,
            "g_a" / self.tbytes_struct,
            "nonce" / self.tbytes_struct,
        )

    def encrypted_chat_discarded_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat_discarded"),
            "signature" / Hex(Const(0x13D6DD27, Int32ul)),
            "id" / Int32ul,
        )

    def encrypted_chat_waiting_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat_waiting"),
            "signature" / Hex(Const(0x3BF703DC, Int32ul)),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "admin_id" / Int32ul,
            "participant_id" / Int32ul,
        )

    def encrypted_chat_old_struct(self):
        return Struct(
            "sname" / Computed("encrypted_chat_old"),
            "signature" / Hex(Const(0x6601D14F, Int32ul)),
            "id" / Int32ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "admin_id" / Int32ul,
            "participant_id" / Int32ul,
            "g_a_or_b" / self.tbytes_struct,
            "nonce" / self.tbytes_struct,
            "key_fingerprint" / Int64ul,
        )

    def encrypted_chat_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x62718A82: LazyBound(lambda: self.encrypted_chat_requested_struct()),
            0xAB7EC0A0: LazyBound(lambda: self.encrypted_chat_empty_struct()),
            0xC878527E: LazyBound(
                lambda: self.encrypted_chat_requested_layer115_struct()
            ),
            0xFA56CE36: LazyBound(lambda: self.encrypted_chat_struct()),
            0xFDA9A7B7: LazyBound(lambda: self.encrypted_chat_requested_old_struct()),
            0x13D6DD27: LazyBound(lambda: self.encrypted_chat_discarded_struct()),
            0x3BF703DC: LazyBound(lambda: self.encrypted_chat_waiting_struct()),
            0x6601D14F: LazyBound(lambda: self.encrypted_chat_old_struct()),
        }
        return "encrypted_chat_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def file_location_struct(self):
        return Struct(
            "sname" / Computed("file_location"),
            "signature" / Hex(Const(0x53D69076, Int32ul)),
            "dc_id" / Int32ul,
            "volume_id" / Int64ul,
            "local_id" / Int32ul,
            "secret" / Int64ul,
        )

    def file_encrypted_location_struct(self):
        return Struct(
            "sname" / Computed("file_encrypted_location"),
            "signature" / Hex(Const(0x55555554, Int32ul)),
            "dc_id" / Int32ul,
            "volume_id" / Int64ul,
            "local_id" / Int32ul,
            "secret" / Int64ul,
            "key" / self.tbytes_struct,
            "iv" / self.tbytes_struct,
        )

    def file_location_unavailable_struct(self):
        return Struct(
            "sname" / Computed("file_location_unavailable"),
            "signature" / Hex(Const(0x7C596B46, Int32ul)),
            "volume_id" / Int64ul,
            "local_id" / Int32ul,
            "secret" / Int64ul,
        )

    def file_location_layer82_struct(self):
        return Struct(
            "sname" / Computed("file_location"),
            "signature" / Hex(Const(0x53D69076, Int32ul)),
            "dc_id" / Int32ul,
            "volume_id" / Int64ul,
            "local_id" / Int32ul,
            "secret" / Int64ul,
        )

    def file_location_layer97_struct(self):
        return Struct(
            "sname" / Computed("file_location_layer97"),
            "signature" / Hex(Const(0x091D11EB, Int32ul)),
            "dc_id" / Int32ul,
            "volume_id" / Int64ul,
            "local_id" / Int32ul,
            "secret" / Int64ul,
            "file_reference" / self.tbytes_struct,
        )

    def file_location_to_be_deprecated_struct(self):
        return Struct(
            "sname" / Computed("file_location_to_be_deprecated"),
            "signature" / Hex(Const(0xBC7FC6CD, Int32ul)),
            "volume_id" / Int64ul,
            "local_id" / Int32ul,
        )

    def file_location_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xBC7FC6CD: LazyBound(lambda: self.file_location_to_be_deprecated_struct()),
            0x091D11EB: LazyBound(lambda: self.file_location_layer97_struct()),
            0x53D69076: LazyBound(lambda: self.file_location_layer82_struct()),
            0x55555554: LazyBound(lambda: self.file_encrypted_location_struct()),
            0x7C596B46: LazyBound(lambda: self.file_location_unavailable_struct()),
        }
        return "file_location_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def game_struct(self):
        return Struct(
            "sname" / Computed("game"),
            "signature" / Hex(Const(0xBDF9653B, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_document=1),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "short_name" / self.tstring_struct,
            "title" / self.tstring_struct,
            "description" / self.tstring_struct,
            "photo" / self.photo_structures("photo"),
            "document"
            / If(this.flags.has_document, self.document_structures("document")),
        )

    # --------------------------------------------------------------------------

    def geo_point_empty_struct(self):
        return Struct(
            "sname" / Computed("geo_point_empty"),
            "signature" / Hex(Const(0x1117DD5F, Int32ul)),
        )

    def geo_point_struct(self):
        return Struct(
            "sname" / Computed("geo_point"),
            "signature" / Hex(Const(0x0296F104, Int32ul)),
            "long" / Float64b,
            "lat" / Float64b,
            "access_hash" / Int64ul,
        )

    def geo_point_layer81_struct(self):
        return Struct(
            "sname" / Computed("geo_point_layer81"),
            "signature" / Hex(Const(0x2049D70C, Int32ul)),
            "long" / Float64b,
            "lat" / Float64b,
        )

    def geo_point_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x0296F104: LazyBound(lambda: self.geo_point_struct()),
            0x1117DD5F: LazyBound(lambda: self.geo_point_empty_struct()),
            0x2049D70C: LazyBound(lambda: self.geo_point_layer81_struct()),
        }
        return "geo_point_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def input_channel_struct(self):
        return Struct(
            "sname" / Computed("input_channel"),
            "signature" / Hex(Const(0xAFEB712E, Int32ul)),
            "channel_id" / Int32ul,
            "access_hash" / Int64ul,
        )

    def input_channel_empty_struct(self):
        return Struct(
            "sname" / Computed("input_channel_empty"),
            "signature" / Hex(Const(0xEE8C1E86, Int32ul)),
        )

    def input_channel_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xAFEB712E: LazyBound(lambda: self.input_channel_struct()),
            0xEE8C1E86: LazyBound(lambda: self.input_channel_empty_struct()),
        }
        return "input_channel_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def input_group_call_struct(self):
        return Struct(
            "sname" / Computed("input_group_call"),
            "signature" / Hex(Const(0xD8AA840F, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
        )

    # --------------------------------------------------------------------------

    def input_message_entity_mention_name_struct(self):
        return Struct(
            "sname" / Computed("input_message_entity_mention_name"),
            "signature" / Hex(Const(0x208E68C9, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
            "user_id" / self.input_user_struct(),
        )

    # --------------------------------------------------------------------------

    def input_sticker_set_animated_emoji_struct(self):
        return Struct("sname" / Computed("input_sticker_set_animated_emoji"))

    def input_sticker_set_dice_struct(self):
        return Struct(
            "sname" / Computed("input_sticker_set_dice"),
            "signature" / Hex(Const(0xE67F520E, Int32ul)),
            "emoticon" / self.tstring_struct,
        )

    def input_sticker_set_empty_struct(self):
        return Struct(
            "sname" / Computed("input_sticker_set_empty"),
            "signature" / Hex(Const(0xFFB62B95, Int32ul)),
        )

    def input_sticker_set_id_struct(self):
        return Struct(
            "sname" / Computed("input_sticker_set_id"),
            "signature" / Hex(Const(0x9DE7A269, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
        )

    def input_sticker_set_short_name_struct(self):
        return Struct(
            "sname" / Computed("input_sticker_set_short_name"),
            "signature" / Hex(Const(0x861CC8A0, Int32ul)),
            "short_name" / self.tstring_struct,
        )

    def input_sticker_set_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x028703C8: LazyBound(
                lambda: self.input_sticker_set_animated_emoji_struct()
            ),
            0xE67F520E: LazyBound(lambda: self.input_sticker_set_dice_struct()),
            0xFFB62B95: LazyBound(lambda: self.input_sticker_set_empty_struct()),
            0x9DE7A269: LazyBound(lambda: self.input_sticker_set_id_struct()),
            0x861CC8A0: LazyBound(lambda: self.input_sticker_set_short_name_struct()),
        }
        return "input_sticker_set_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def input_user_empty_struct(self):
        return Struct(
            "sname" / Computed("input_user_empty"),
            "signature" / Hex(Const(0xB98886CF, Int32ul)),
        )

    def input_user_struct(self):
        return Struct(
            "sname" / Computed("input_user"),
            "signature" / Hex(Const(0xD8292816, Int32ul)),
            "user_id" / Int32ul,
            "access_hash" / Int64ul,
        )

    # --------------------------------------------------------------------------

    def keyboard_button_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button"),
            "signature" / Hex(Const(0xA2FA4880, Int32ul)),
            "text" / self.tstring_struct,
        )

    def keyboard_button_buy_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_buy"),
            "signature" / Hex(Const(0xAFD93FBB, Int32ul)),
            "text" / self.tstring_struct,
        )

    def keyboard_button_request_phone_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_request_phone"),
            "signature" / Hex(Const(0xB16A6C29, Int32ul)),
            "text" / self.tstring_struct,
        )

    def keyboard_button_request_poll_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_request_poll"),
            "signature" / Hex(Const(0xBBC7515D, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_quiz=1),
            "quiz" / If(this.flags.has_quiz, self.tbool_struct),
            "text" / self.tstring_struct,
        )

    def keyboard_button_request_geo_location_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_request_geo_location"),
            "signature" / Hex(Const(0xFC796B3F, Int32ul)),
            "text" / self.tstring_struct,
        )

    def keyboard_button_switch_inline_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_switch_inline"),
            "signature" / Hex(Const(0x0568A748, Int32ul)),
            "flags" / FlagsEnum(Int32ul, same_peer=1),
            "text" / self.tstring_struct,
            "query" / self.tstring_struct,
        )

    def keyboard_button_url_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_url"),
            "signature" / Hex(Const(0x258AFF05, Int32ul)),
            "text" / self.tstring_struct,
            "url" / self.tstring_struct,
        )

    def keyboard_button_url_auth_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_url_auth"),
            "signature" / Hex(Const(0x10B78D29, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_fwd_text=1),
            "text" / self.tstring_struct,
            "fwd_text" / If(this.flags.has_fwd_text, self.tstring_struct),
            "url" / self.tstring_struct,
            "button_id" / Int32ul,
        )

    def keyboard_button_game_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_game"),
            "signature" / Hex(Const(0x50F41CCF, Int32ul)),
            "text" / self.tstring_struct,
        )

    def keyboard_button_callback_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_callback"),
            "signature" / Hex(Const(0x683A5E46, Int32ul)),
            "text" / self.tstring_struct,
            "data" / self.tbytes_struct,
        )

    def keyboard_button_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x10B78D29: LazyBound(lambda: self.keyboard_button_url_auth_struct()),
            0xBBC7515D: LazyBound(lambda: self.keyboard_button_request_poll_struct()),
            0xA2FA4880: LazyBound(lambda: self.keyboard_button_struct()),
            0xAFD93FBB: LazyBound(lambda: self.keyboard_button_buy_struct()),
            0xB16A6C29: LazyBound(lambda: self.keyboard_button_request_phone_struct()),
            0xFC796B3F: LazyBound(
                lambda: self.keyboard_button_request_geo_location_struct()
            ),
            0x0568A748: LazyBound(lambda: self.keyboard_button_switch_inline_struct()),
            0x258AFF05: LazyBound(lambda: self.keyboard_button_url_struct()),
            0x50F41CCF: LazyBound(lambda: self.keyboard_button_game_struct()),
            0x683A5E46: LazyBound(lambda: self.keyboard_button_callback_struct()),
        }
        return "keyboard_button_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    def keyboard_button_row_struct(self):
        return Struct(
            "sname" / Computed("keyboard_button_row"),
            "signature" / Hex(Const(0x77608B83, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "keyboard_buttons_row_num" / Int32ul,
            "keyboard_buttons_row_array"
            / Array(
                this.keyboard_buttons_row_num,
                self.keyboard_button_structures("keyboard_button"),
            ),
        )

    # --------------------------------------------------------------------------

    def mask_coords_struct(self):
        return Struct(
            "sname" / Computed("mask_coords"),
            "signature" / Hex(Const(0xAED6DBB2, Int32ul)),
            "n" / Int32ul,
            "x" / Float64b,
            "y" / Float64b,
            "zoom" / Float64b,
        )

    # --------------------------------------------------------------------------

    def message_action_chat_create_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_create"),
            "signature" / Hex(Const(0xA6638B9A, Int32ul)),
            "title" / self.tstring_struct,
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "users_num" / Int32ul,
            "users" / Array(this.users_num, Int32ul),
        )

    def message_action_chat_delete_photo_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_delete_photo"),
            "signature" / Hex(Const(0x95E3FBEF, Int32ul)),
        )

    def message_action_chat_delete_user_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_delete_user"),
            "signature" / Hex(Const(0xB2AE9B0C, Int32ul)),
            "user_id" / Int32ul,
        )

    def message_action_chat_edit_title_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_edit_title"),
            "signature" / Hex(Const(0xB5A1CE5A, Int32ul)),
            "title" / self.tstring_struct,
        )

    def message_action_empty_struct(self):
        return Struct(
            "sname" / Computed("message_action_empty"),
            "signature" / Hex(Const(0xB6AEF7B0, Int32ul)),
        )

    def message_action_ttl_change_struct(self):
        return Struct(
            "sname" / Computed("message_action_ttl_change"),
            "signature" / Hex(Const(0x55555552, Int32ul)),
            "ttl_seconds" / Int32ul,
        )

    def message_action_user_joined_struct(self):
        return Struct(
            "sname" / Computed("message_action_user_joined"),
            "signature" / Hex(Const(0x55555550, Int32ul)),
        )

    def message_action_login_unknown_location_struct(self):
        return Struct(
            "sname" / Computed("message_action_login_unknown_location"),
            "signature" / Hex(Const(0x555555F5, Int32ul)),
            "title" / self.tstring_struct,
            "address" / self.tstring_struct,
        )

    def message_action_chat_add_user_old_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_add_user_old"),
            "signature" / Hex(Const(0x5E3CFC4B, Int32ul)),
            "user_id" / Int32ul,
        )

    def message_action_bot_allowed_struct(self):
        return Struct(
            "sname" / Computed("message_action_bot_allowed"),
            "signature" / Hex(Const(0xABE9AFFE, Int32ul)),
            "domain" / self.tstring_struct,
        )

    def message_action_channel_create_struct(self):
        return Struct(
            "sname" / Computed("message_action_channel_create"),
            "signature" / Hex(Const(0x95D2AC92, Int32ul)),
            "title" / self.tstring_struct,
        )

    def message_action_channel_migrate_from_struct(self):
        return Struct(
            "sname" / Computed("message_action_channel_migrate_from"),
            "signature" / Hex(Const(0xB055EAEE, Int32ul)),
            "title" / self.tstring_struct,
            "chat_id" / Int32ul,
        )

    def message_action_chat_edit_photo_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_edit_photo"),
            "signature" / Hex(Const(0x7FCB13A8, Int32ul)),
            "photo" / self.photo_structures("photo"),
        )

    def message_action_history_clear_struct(self):
        return Struct(
            "sname" / Computed("message_action_history_clear"),
            "signature" / Hex(Const(0x9FBAB604, Int32ul)),
        )

    def message_action_game_score_struct(self):
        return Struct(
            "sname" / Computed("message_action_game_score"),
            "signature" / Hex(Const(0x92A72876, Int32ul)),
            "game_id" / Int64ul,
            "score" / Int32ul,
        )

    def message_action_pin_message_struct(self):
        return Struct(
            "sname" / Computed("message_action_pin_message"),
            "signature" / Hex(Const(0x94BD38ED, Int32ul)),
        )

    def message_action_phone_call_struct(self):
        return Struct(
            "sname" / Computed("message_action_phone_call"),
            "signature" / Hex(Const(0x80E11A7F, Int32ul)),
            "flags" / FlagsEnum(Int32ul, is_discarded=1, has_duration=2, is_video=4),
            "call_id" / Int64ul,
            "discard_reason"
            / If(
                this.flags.is_discarded,
                self.phone_call_discard_reason_structures("discard_reason"),
            ),
            "duration" / If(this.flags.has_duration, Int32ul),
        )

    def message_action_contact_sign_up_struct(self):
        return Struct(
            "sname" / Computed("message_action_contact_sign_up"),
            "signature" / Hex(Const(0xF3F25F76, Int32ul)),
        )

    def message_action_secure_values_sent_struct(self):
        return Struct(
            "sname" / Computed("message_action_secure_values_sent"),
            "signature" / Hex(Const(0xD95C6154, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "secure_values_num" / Int32ul,
            "secure_value_array"
            / Array(
                this.secure_values_num,
                self.secure_value_type_structures("secure_value"),
            ),
        )

    def message_action_chat_joined_by_link_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_joined_by_link"),
            "signature" / Hex(Const(0xF89CF5E8, Int32ul)),
            "inviter_id" / Int32ul,
        )

    def message_action_custom_action_struct(self):
        return Struct(
            "sname" / Computed("message_action_custom_action"),
            "signature" / Hex(Const(0xFAE69F56, Int32ul)),
            "message" / self.tstring_struct,
        )

    def message_action_payment_sent_struct(self):
        return Struct(
            "sname" / Computed("message_action_payment_sent_struct"),
            "signature" / Hex(Const(0x40699CD0, Int32ul)),
            "currency" / self.tstring_struct,
            "total_amount" / Int64ul,
        )

    def message_action_screenshot_taken_struct(self):
        return Struct(
            "sname" / Computed("message_action_screenshot_taken"),
            "signature" / Hex(Const(0x4792929B, Int32ul)),
        )

    def message_action_chat_add_user_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_add_user"),
            "signature" / Hex(Const(0x488A7337, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "user_array_num" / Int32ul,
            "user_array" / Array(this.user_array_num, Int32ul),
        )

    def message_action_chat_migrate_to_struct(self):
        return Struct(
            "sname" / Computed("message_action_chat_migrate_to"),
            "signature" / Hex(Const(0x51BDB021, Int32ul)),
            "channel_id" / Int32ul,
        )

    def message_action_user_updated_photo_struct(self):
        return Struct(
            "sname" / Computed("message_action_user_updated_photo"),
            "signature" / Hex(Const(0x55555551, Int32ul)),
            "new_user_photo" / self.user_profile_photo_structures("new_user_photo"),
        )

    def message_action_created_broadcast_list_struct(self):
        return Struct(
            "sname" / Computed("message_action_created_broadcast_list"),
            "signature" / Hex(Const(0x55555557, Int32ul)),
        )

    def message_encrypted_action_struct(self):
        return Struct(
            "sname" / Computed("message_encrypted_action"),
            "signature" / Hex(Const(0x555555F7, Int32ul)),
            "encrypted_action"
            / self.decrypted_message_action_structures("encrypted_action"),
        )

    def message_action_group_call_struct(self):
        return Struct(
            "sname" / Computed("message_action_group_call"),
            "signature" / Hex(Const(0x7A0D7F42, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_duration=1),
            "call" / self.input_group_call_struct(),
            "duration" / If(this.flags.has_duration, Int32ul),
        )

    def message_action_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x80E11A7F: LazyBound(lambda: self.message_action_phone_call_struct()),
            0x92A72876: LazyBound(lambda: self.message_action_game_score_struct()),
            0x94BD38ED: LazyBound(lambda: self.message_action_pin_message_struct()),
            0x95D2AC92: LazyBound(lambda: self.message_action_channel_create_struct()),
            0x95E3FBEF: LazyBound(
                lambda: self.message_action_chat_delete_photo_struct()
            ),
            0x9FBAB604: LazyBound(lambda: self.message_action_history_clear_struct()),
            0xA6638B9A: LazyBound(lambda: self.message_action_chat_create_struct()),
            0xABE9AFFE: LazyBound(lambda: self.message_action_bot_allowed_struct()),
            0xB055EAEE: LazyBound(
                lambda: self.message_action_channel_migrate_from_struct()
            ),
            0xB2AE9B0C: LazyBound(
                lambda: self.message_action_chat_delete_user_struct()
            ),
            0xB5A1CE5A: LazyBound(lambda: self.message_action_chat_edit_title_struct()),
            0xB6AEF7B0: LazyBound(lambda: self.message_action_empty_struct()),
            0xD95C6154: LazyBound(
                lambda: self.message_action_secure_values_sent_struct()
            ),
            0xF3F25F76: LazyBound(lambda: self.message_action_contact_sign_up_struct()),
            0xF89CF5E8: LazyBound(
                lambda: self.message_action_chat_joined_by_link_struct()
            ),
            0xFAE69F56: LazyBound(lambda: self.message_action_custom_action_struct()),
            0x40699CD0: LazyBound(lambda: self.message_action_payment_sent_struct()),
            0x4792929B: LazyBound(
                lambda: self.message_action_screenshot_taken_struct()
            ),
            0x488A7337: LazyBound(lambda: self.message_action_chat_add_user_struct()),
            0x51BDB021: LazyBound(lambda: self.message_action_chat_migrate_to_struct()),
            0x55555550: LazyBound(lambda: self.message_action_user_joined_struct()),
            0x55555551: LazyBound(
                lambda: self.message_action_user_updated_photo_struct()
            ),
            0x55555552: LazyBound(lambda: self.message_action_ttl_change_struct()),
            0x55555557: LazyBound(
                lambda: self.message_action_created_broadcast_list_struct()
            ),
            0x555555F5: LazyBound(
                lambda: self.message_action_login_unknown_location_struct()
            ),
            0x555555F7: LazyBound(lambda: self.message_encrypted_action_struct()),
            0x5E3CFC4B: LazyBound(
                lambda: self.message_action_chat_add_user_old_struct()
            ),
            0x7A0D7F42: LazyBound(lambda: self.message_action_group_call_struct()),
            0x7FCB13A8: LazyBound(lambda: self.message_action_chat_edit_photo_struct()),
        }
        return "message_action_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def message_entity_italic_struct(self):
        return Struct(
            "sname" / Computed("message_entity_italic"),
            "signature" / Hex(Const(0x826F8B60, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_phone_struct(self):
        return Struct(
            "sname" / Computed("message_entity_phone"),
            "signature" / Hex(Const(0x9B69E34B, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_unknown_struct(self):
        return Struct(
            "sname" / Computed("message_entity_unknown"),
            "signature" / Hex(Const(0xBB92BA95, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_bank_card_struct(self):
        return Struct(
            "sname" / Computed("message_entity_bank_card"),
            "signature" / Hex(Const(0x761E6AF4, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_blockquote_struct(self):
        return Struct(
            "sname" / Computed("message_entity_blockquote"),
            "signature" / Hex(Const(0x020DF5D0, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_bold_struct(self):
        return Struct(
            "sname" / Computed("message_entity_bold"),
            "signature" / Hex(Const(0xBD610BC9, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_mention_struct(self):
        return Struct(
            "sname" / Computed("message_entity_mention"),
            "signature" / Hex(Const(0xFA04579D, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_code_struct(self):
        return Struct(
            "sname" / Computed("message_entity_code"),
            "signature" / Hex(Const(0x28A20571, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_mention_name_struct(self):
        return Struct(
            "sname" / Computed("message_entity_mention_name"),
            "signature" / Hex(Const(0x352DCA58, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
            "user_id" / Int32ul,
        )

    def message_entity_cashtag_struct(self):
        return Struct(
            "sname" / Computed("message_entity_cashtag"),
            "signature" / Hex(Const(0x4C4E743F, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_email_struct(self):
        return Struct(
            "sname" / Computed("message_entity_email"),
            "signature" / Hex(Const(0x64E475C2, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_bot_command_struct(self):
        return Struct(
            "sname" / Computed("message_entity_bot_command"),
            "signature" / Hex(Const(0x6CEF8AC7, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_url_struct(self):
        return Struct(
            "sname" / Computed("message_entity_url"),
            "signature" / Hex(Const(0x6ED02538, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_hashtag_struct(self):
        return Struct(
            "sname" / Computed("message_entity_hashtag"),
            "signature" / Hex(Const(0x6F635B0D, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_pre_struct(self):
        return Struct(
            "sname" / Computed("message_entity_pre"),
            "signature" / Hex(Const(0x73924BE0, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
            "language" / self.tstring_struct,
        )

    def message_entity_text_url_struct(self):
        return Struct(
            "sname" / Computed("message_entity_text_url"),
            "signature" / Hex(Const(0x76A6D327, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
            "url" / self.tstring_struct,
        )

    def message_entity_strike_struct(self):
        return Struct(
            "sname" / Computed("message_entity_strike"),
            "signature" / Hex(Const(0xBF0693D4, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_underline_struct(self):
        return Struct(
            "sname" / Computed("message_entity_underline"),
            "signature" / Hex(Const(0x9C4E7E8B, Int32ul)),
            "offset" / Int32ul,
            "length" / Int32ul,
        )

    def message_entity_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x9C4E7E8B: LazyBound(lambda: self.message_entity_underline_struct()),
            0xBF0693D4: LazyBound(lambda: self.message_entity_strike_struct()),
            0x761E6AF4: LazyBound(lambda: self.message_entity_bank_card_struct()),
            0x020DF5D0: LazyBound(lambda: self.message_entity_blockquote_struct()),
            0x826F8B60: LazyBound(lambda: self.message_entity_italic_struct()),
            0x9B69E34B: LazyBound(lambda: self.message_entity_phone_struct()),
            0xBB92BA95: LazyBound(lambda: self.message_entity_unknown_struct()),
            0xBD610BC9: LazyBound(lambda: self.message_entity_bold_struct()),
            0xFA04579D: LazyBound(lambda: self.message_entity_mention_struct()),
            0x208E68C9: LazyBound(
                lambda: self.input_message_entity_mention_name_struct()
            ),
            0x28A20571: LazyBound(lambda: self.message_entity_code_struct()),
            0x352DCA58: LazyBound(lambda: self.message_entity_mention_name_struct()),
            0x4C4E743F: LazyBound(lambda: self.message_entity_cashtag_struct()),
            0x64E475C2: LazyBound(lambda: self.message_entity_email_struct()),
            0x6CEF8AC7: LazyBound(lambda: self.message_entity_bot_command_struct()),
            0x6ED02538: LazyBound(lambda: self.message_entity_url_struct()),
            0x6F635B0D: LazyBound(lambda: self.message_entity_hashtag_struct()),
            0x73924BE0: LazyBound(lambda: self.message_entity_pre_struct()),
            0x76A6D327: LazyBound(lambda: self.message_entity_text_url_struct()),
        }
        return "message_entity_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def message_empty_struct(self):
        return Struct(
            "sname" / Computed("message_empty"),
            "signature" / Hex(Const(0x83E5DE54, Int32ul)),
            "id" / Int32ul,
            # It seems empty messages without 'to_id' exists.
            "_extra_signature" / Peek(Int32ul),
            "to_id"
            / IfThenElse(
                this._extra_signature, self.peer_structures("to_id"), Terminated
            ),
        )

    # --------------------------------------------------------------------------

    def message_fwd_header_struct(self):
        return Struct(
            "sname" / Computed("message_fwd_header"),
            "signature" / Hex(Const(0x353A686B, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_from_id=1,
                has_channel_id=2,
                has_channel_post=4,
                has_post_author=8,
                has_saved_from_peer=16,
                has_from_name=32,
                has_psa_type=64,
            ),
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "from_name" / If(this.flags.has_from_name, self.tstring_struct),
            "date" / self.ttimestamp_struct,
            "channel_id" / If(this.flags.has_channel_id, Int32ul),
            "channel_post" / If(this.flags.has_channel_post, Int32ul),
            "post_author" / If(this.flags.has_post_author, self.tstring_struct),
            "saved_from_peer"
            / If(
                this.flags.has_saved_from_peer, self.peer_structures("saved_from_peer")
            ),
            "saved_from_msg_id" / If(this.flags.has_saved_from_peer, Int32ul),
            "psa_type" / If(this.flags.has_psa_type, self.tstring_struct),
        )

    def message_fwd_header_layer112_struct(self):
        return Struct(
            "sname" / Computed("message_fwd_header_layer112"),
            "signature" / Hex(Const(0xEC338270, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_from_id=1,
                has_channel_id=2,
                has_channel_post=4,
                has_post_author=8,
                has_saved_from_peer=16,
                has_from_name=32,
            ),
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "from_name" / If(this.flags.has_from_name, self.tstring_struct),
            "date" / self.ttimestamp_struct,
            "channel_id" / If(this.flags.has_channel_id, Int32ul),
            "channel_post" / If(this.flags.has_channel_post, Int32ul),
            "post_author" / If(this.flags.has_post_author, self.tstring_struct),
            "saved_from_peer"
            / If(
                this.flags.has_saved_from_peer, self.peer_structures("saved_from_peer")
            ),
            "saved_from_msg_id" / If(this.flags.has_saved_from_peer, Int32ul),
        )

    def message_fwd_header_layer68_struct(self):
        return Struct(
            "sname" / Computed("message_fwd_header_layer68"),
            "signature" / Hex(Const(0xC786DDCB, Int32ul)),
            "flags"
            / FlagsEnum(Int32ul, has_from_id=1, has_channel_id=2, has_channel_post=4),
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "channel_id" / If(this.flags.has_channel_id, Int32ul),
            "channel_post" / If(this.flags.has_channel_post, Int32ul),
        )

    def message_fwd_header_layer72_struct(self):
        return Struct(
            "sname" / Computed("message_fwd_header_layer72"),
            "signature" / Hex(Const(0xFADFF4AC, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_from_id=1,
                has_channel_id=2,
                has_channel_post=4,
                has_post_author=8,
            ),
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "channel_id" / If(this.flags.has_channel_id, Int32ul),
            "channel_post" / If(this.flags.has_channel_post, Int32ul),
            "post_author" / If(this.flags.has_post_author, self.tstring_struct),
        )

    def message_fwd_header_layer96_struct(self):
        return Struct(
            "sname" / Computed("message_fwd_header_layer96"),
            "signature" / Hex(Const(0x559EBE6D, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_from_id=1,
                has_channel_id=2,
                has_channel_post=4,
                has_post_author=8,
                has_saved_from_peer=16,
            ),
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "channel_id" / If(this.flags.has_channel_id, Int32ul),
            "channel_post" / If(this.flags.has_channel_post, Int32ul),
            "post_author" / If(this.flags.has_post_author, self.tstring_struct),
            "saved_from_peer"
            / If(
                this.flags.has_saved_from_peer, self.peer_structures("saved_from_peer")
            ),
            "saved_from_msg_id" / If(this.flags.has_saved_from_peer, Int32ul),
        )

    def message_fwd_header_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x353A686B: LazyBound(lambda: self.message_fwd_header_struct()),
            0xC786DDCB: LazyBound(lambda: self.message_fwd_header_layer68_struct()),
            0xEC338270: LazyBound(lambda: self.message_fwd_header_layer112_struct()),
            0xFADFF4AC: LazyBound(lambda: self.message_fwd_header_layer72_struct()),
            0x559EBE6D: LazyBound(lambda: self.message_fwd_header_layer96_struct()),
        }
        return "message_fwd_header_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def message_reactions_struct(self):
        return Struct(
            "sname" / Computed("message_reactions"),
            "signature" / Hex(Const(0xB87A24D1, Int32ul)),
            "flags" / FlagsEnum(Int32ul, min=1),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "reaction_count_num" / Int32ul,
            "reaction_count_array"
            / Array(this.reaction_count_num, self.reaction_count_struct()),
        )

    # --------------------------------------------------------------------------

    def message_media_empty_struct(self):
        return Struct(
            "sname" / Computed("message_media_empty"),
            "signature" / Hex(Const(0x3DED6320, Int32ul)),
        )

    def message_media_invoice_struct(self):
        return Struct(
            "sname" / Computed("message_media_invoice"),
            "signature" / Hex(Const(0x84551347, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_photo=1,
                shipping_address_requested=2,
                has_receipt_msg_id=4,
                is_test=8,
            ),
            "title" / self.tstring_struct,
            "description" / self.tstring_struct,
            "photo" / If(this.flags.has_photo, self.web_document_structures("photo")),
            "receipt_msg_id" / If(this.flags.has_receipt_msg_id, Int32ul),
            "currency" / self.tstring_struct,
            "total_amount" / Int64ul,
            "start_param" / self.tstring_struct,
        )

    def message_media_document_struct(self):
        return Struct(
            "sname" / Computed("message_media_document"),
            "signature" / Hex(Const(0x9CB070D7, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_document=1, has_ttl_seconds=4),
            "document"
            / If(this.flags.has_document, self.document_structures("document")),
            "ttl_seconds" / If(this.flags.has_ttl_seconds, Int32ul),
        )

    def message_media_unsupported_struct(self):
        return Struct(
            "sname" / Computed("message_media_unsupported"),
            "signature" / Hex(Const(0x9F84F49E, Int32ul)),
        )

    def message_media_video_old_struct(self):
        return Struct(
            "sname" / Computed("message_media_video_old"),
            "signature" / Hex(Const(0xA2D24290, Int32ul)),
            "video_unused" / self.video_structures("video_unused"),
        )

    def message_media_web_page_struct(self):
        return "message_media_web_page" / Struct(
            "sname" / Computed("message_media_web_page"),
            "signature" / Hex(Const(0xA32DD600, Int32ul)),
            "webpage" / self.web_page_structures("webpage"),
        )

    def message_media_photo_layer74_struct(self):
        return Struct(
            "sname" / Computed("message_media_photo_layer74"),
            "signature" / Hex(Const(0xB5223B0F, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_photo=1, has_caption=2, has_ttl=4),
            "photo" / If(this.flags.has_photo, self.photo_structures("photo")),
            "caption_legacy" / If(this.flags.has_caption, self.tstring_struct),
            "ttl_seconds" / If(this.flags.has_ttl, Int32ul),
        )

    def message_media_audio_layer45_struct(self):
        return Struct(
            "sname" / Computed("message_media_audio_layer45"),
            "signature" / Hex(Const(0xC6B68300, Int32ul)),
            "audio" / self.audio_structures("audio"),
        )

    def message_media_photo_old_struct(self):
        return Struct(
            "sname" / Computed("message_media_photo_old"),
            "signature" / Hex(Const(0xC8C45A2A, Int32ul)),
            "photo" / self.photo_structures("photo"),
        )

    def message_media_contact_struct(self):
        return Struct(
            "sname" / Computed("message_media_contact"),
            "signature" / Hex(Const(0xCBF24940, Int32ul)),
            "phone_number" / self.tstring_struct,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "vcard" / self.tstring_struct,
            "user_id" / Int32ul,
        )

    def message_media_document_layer68_struct(self):
        return Struct(
            "sname" / Computed("message_media_document_layer68"),
            "signature" / Hex(Const(0xF3E02EA8, Int32ul)),
            "document" / self.document_structures("document"),
            "caption_legacy" / self.tstring_struct,
        )

    def message_media_game_struct(self):
        return Struct(
            "sname" / Computed("message_media_game"),
            "signature" / Hex(Const(0xFDB19008, Int32ul)),
            "game" / self.game_struct(),
        )

    def message_media_unsupported_old_struct(self):
        return Struct(
            "sname" / Computed("message_media_unsupported_old"),
            "signature" / Hex(Const(0x29632A36, Int32ul)),
            "bytes" / self.tbytes_struct,
        )

    def message_media_venue_struct(self):
        return Struct(
            "sname" / Computed("message_media_venue"),
            "signature" / Hex(Const(0x2EC0533F, Int32ul)),
            "geo" / self.geo_point_structures("geo"),
            "title" / self.tstring_struct,
            "address" / self.tstring_struct,
            "provider" / self.tstring_struct,
            "venue_id" / self.tstring_struct,
            "venue_type" / self.tstring_struct,
        )

    def message_media_document_old_struct(self):
        return Struct(
            "sname" / Computed("message_media_document_old"),
            "signature" / Hex(Const(0x2FDA2204, Int32ul)),
            "document" / self.document_structures("document"),
        )

    def message_media_photo_layer68_struct(self):
        return Struct(
            "sname" / Computed("message_media_photo_layer68"),
            "signature" / Hex(Const(0x3D8CE53D, Int32ul)),
            "photo" / self.photo_structures("photo"),
            "caption_legacy" / self.tstring_struct,
        )

    def message_media_poll_struct(self):
        return Struct(
            "sname" / Computed("message_media_poll"),
            "signature" / Hex(Const(0x4BD6E798, Int32ul)),
            "poll" / self.poll_struct(),
            "results" / self.poll_results_structures("results"),
        )

    def message_media_geo_struct(self):
        return Struct(
            "sname" / Computed("message_media_geo"),
            "signature" / Hex(Const(0x56E0D474, Int32ul)),
            "geo" / self.geo_point_structures("geo"),
        )

    def message_media_video_layer45_struct(self):
        return Struct(
            "sname" / Computed("message_media_video_layer45"),
            "signature" / Hex(Const(0x5BCF1675, Int32ul)),
            "video_unused" / self.video_structures("video_unused"),
            "caption_legacy" / self.tstring_struct,
        )

    def message_media_contact_layer81_struct(self):
        return Struct(
            "sname" / Computed("message_media_contact_layer81"),
            "signature" / Hex(Const(0x5E7D2F39, Int32ul)),
            "phone_number" / self.tstring_struct,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "user_id" / Int32ul,
        )

    def message_media_dice_struct(self):
        return Struct(
            "sname" / Computed("message_media_dice"),
            "signature" / Hex(Const(0x3F7EE58B, Int32ul)),
            "emoticon" / self.tstring_struct,
        )

    def message_media_dice_layer111_struct(self):
        return Struct(
            "sname" / Computed("message_media_dice_layer111"),
            "signature" / Hex(Const(0x638FE46B, Int32ul)),
            "value" / Int32ul,
        )

    def message_media_photo_struct(self):
        return Struct(
            "sname" / Computed("message_media_photo"),
            "signature" / Hex(Const(0x695150D7, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_photo=1, has_ttl=4),
            "photo" / If(this.flags.has_photo, self.photo_structures("photo")),
            "ttl_seconds" / If(this.flags.has_ttl, Int32ul),
        )

    def message_media_venue_layer71_struct(self):
        return Struct(
            "sname" / Computed("message_media_venue_layer71"),
            "signature" / Hex(Const(0x7912B71F, Int32ul)),
            "geo" / self.geo_point_structures("geo"),
            "title" / self.tstring_struct,
            "address" / self.tstring_struct,
            "provider" / self.tstring_struct,
            "venue_id" / self.tstring_struct,
        )

    def message_media_geo_live_struct(self):
        return Struct(
            "sname" / Computed("message_media_geo_live"),
            "signature" / Hex(Const(0x7C3C2609, Int32ul)),
            "geo" / self.geo_point_structures("geo"),
            "period" / Int32ul,
        )

    def message_media_document_layer74_struct(self):
        return Struct(
            "sname" / Computed("message_media_document_layer74"),
            "signature" / Hex(Const(0x7C4414D3, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_document=1, has_caption=2, has_ttl=4),
            "document"
            / If(this.flags.has_document, self.document_structures("document")),
            "caption_legacy" / If(this.flags.has_caption, self.tstring_struct),
            "ttl_seconds" / If(this.flags.has_ttl, Int32ul),
        )

    def message_media_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x3F7EE58B: LazyBound(lambda: self.message_media_dice_struct()),
            0x638FE46B: LazyBound(lambda: self.message_media_dice_layer111_struct()),
            0x3DED6320: LazyBound(lambda: self.message_media_empty_struct()),
            0xA32DD600: LazyBound(lambda: self.message_media_web_page_struct()),
            0x84551347: LazyBound(lambda: self.message_media_invoice_struct()),
            0x9CB070D7: LazyBound(lambda: self.message_media_document_struct()),
            0x9F84F49E: LazyBound(lambda: self.message_media_unsupported_struct()),
            0xA2D24290: LazyBound(lambda: self.message_media_video_old_struct()),
            0xB5223B0F: LazyBound(lambda: self.message_media_photo_layer74_struct()),
            0xC6B68300: LazyBound(lambda: self.message_media_audio_layer45_struct()),
            0xC8C45A2A: LazyBound(lambda: self.message_media_photo_old_struct()),
            0xCBF24940: LazyBound(lambda: self.message_media_contact_struct()),
            0xF3E02EA8: LazyBound(lambda: self.message_media_document_layer68_struct()),
            0xFDB19008: LazyBound(lambda: self.message_media_game_struct()),
            0x29632A36: LazyBound(lambda: self.message_media_unsupported_old_struct()),
            0x2EC0533F: LazyBound(lambda: self.message_media_venue_struct()),
            0x2FDA2204: LazyBound(lambda: self.message_media_document_old_struct()),
            0x3D8CE53D: LazyBound(lambda: self.message_media_photo_layer68_struct()),
            0x4BD6E798: LazyBound(lambda: self.message_media_poll_struct()),
            0x56E0D474: LazyBound(lambda: self.message_media_geo_struct()),
            0x5BCF1675: LazyBound(lambda: self.message_media_video_layer45_struct()),
            0x5E7D2F39: LazyBound(lambda: self.message_media_contact_layer81_struct()),
            0x695150D7: LazyBound(lambda: self.message_media_photo_struct()),
            0x7912B71F: LazyBound(lambda: self.message_media_venue_layer71_struct()),
            0x7C3C2609: LazyBound(lambda: self.message_media_geo_live_struct()),
            0x7C4414D3: LazyBound(lambda: self.message_media_document_layer74_struct()),
        }
        return "message_media_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def message_forwarded_old_struct(self):
        return Struct(
            "sname" / Computed("message_forwarded_old"),
            "signature" / Hex(Const(0x05F46804, Int32ul)),
            "id" / Int32ul,
            "fwd_from_id" / Int32ul,
            "fwd_from_date" / self.ttimestamp_struct,
            "from_id" / Int32ul,
            "to_id" / self.peer_structures("to_id"),
            "out" / self.tbool_struct,
            "unread" / self.tbool_struct,
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / self.message_media_structures("media"),
        )

    def message_forwarded_old2_struct(self):
        return Struct(
            "sname" / Computed("message_forwarded_old2"),
            "signature" / Hex(Const(0xA367E716, Int32ul)),
            "flags"
            / FlagsEnum(Int32ul, unread=1, out=2, mentioned=16, media_unread=32),
            "id" / Int32ul,
            "fwd_from_id" / Int32ul,
            "fwd_from_date" / Int32ul,
            "from_id" / Int32ul,
            "to_id" / self.peer_structures("to_id"),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / self.message_media_structures("media"),
        )

    def message_old3_struct(self):
        return Struct(
            "sname" / Computed("message_old3"),
            "signature" / Hex(Const(0xA7AB1991, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                unread=1,
                out=2,
                is_forwarded=4,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
            ),
            "id" / Int32ul,
            "from_id" / Int32ul,
            "to_id" / self.peer_structures("to_id"),
            "fwd_from_id" / If(this.flags.is_forwarded, Int32ul),
            "fwd_from_date" / If(this.flags.is_forwarded, Int32ul),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / self.message_media_structures("media"),
        )

    def message_service_struct(self):
        return Struct(
            "sname" / Computed("message_service"),
            "signature" / Hex(Const(0x9E19A1F6, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                unread=1,
                out=2,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                has_from_id=256,
                post=16384,
                silent=8192,
                is_grouped_id=131072,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "to_id" / self.peer_structures("to_id"),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "action" / self.message_action_structures("action"),
        )

    def message_service_old_struct(self):
        return Struct(
            "sname" / Computed("message_service_old"),
            "signature" / Hex(Const(0x9F8D60BB, Int32ul)),
            "id" / Int32ul,
            "from_id" / Int32ul,
            "to_id" / self.peer_structures("to_id"),
            "out" / self.tbool_struct,
            "unread" / self.tbool_struct,
            "date" / self.ttimestamp_struct,
            "action" / self.message_action_structures("action"),
        )

    def message_secret_struct(self):
        return Struct(
            "sname" / Computed("message_secret"),
            "signature" / Hex(Const(0x555555FA, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                unread=1,
                out=2,
                is_reply_to_random_id=8,
                mentioned=16,
                media_unread=32,
                has_via_bot_name=2048,
                has_grouped_id=131072,
            ),
            "id" / Int32ul,
            "ttl" / Int32ul,
            "from_id" / Int32ul,
            "to_id" / self.peer_structures("to_id"),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / self.message_media_structures("media"),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "message_entity_num" / Int32ul,
            "message_entity_array"
            / Array(
                this.message_entity_num,
                self.message_entity_structures("message_entity"),
            ),
            "via_bot_name" / If(this.flags.has_via_bot_name, self.tstring_struct),
            "reply_to_random_id" / If(this.flags.is_reply_to_random_id, Int64ul),
            "grouped_id" / If(this.flags.has_grouped_id, Int64ul),
            "UNPARSED" / GreedyBytes,
        )

    def message_layer72_struct(self):
        return Struct(
            "sname" / Computed("message_layer72"),
            "signature" / Hex(Const(0x90DDDC11, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                out=2,
                forwarded=4,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                has_reply_markup=64,
                has_entities=128,
                has_from_id=256,
                has_media=512,
                has_views=1024,
                is_via_bot=2048,
                silent=8192,
                post=16384,
                is_edited=32768,
                has_author=65536,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "to_id_type"
            / FlagsEnum(Int32ul, channel=0xBDDDE532, chat=0xBAD0E5BB, user=0x9DB1BC6D),
            "to_id" / Int32ul,
            "fwd_from"
            / If(this.flags.forwarded, self.message_fwd_header_structures("fwd_from")),
            "via_bot_id" / If(this.flags.is_via_bot, Int32ul),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / If(this.flags.has_media, self.message_media_structures("media")),
            # The following two fields are copied from media, ignored.
            "_media_ttl" / Computed("ignored"),
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(
                this.flags.has_reply_markup,
                self.reply_markup_structures("reply_markup"),
            ),
            "entities"
            / If(
                this.flags.has_entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
            "views" / If(this.flags.has_views, Int32ul),
            "edit_timestamp" / If(this.flags.is_edited, Int32ul),
            "post_author" / If(this.flags.has_author, Int32ul),
        )

    def message_service_layer48_struct(self):
        return Struct(
            "sname" / Computed("message_service_layer48"),
            "signature" / Hex(Const(0xC06B9607, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                unread=1,
                out=2,
                mentioned=16,
                media_unread=32,
                has_from_id=256,
                is_via_bot=2048,
                post=16384,
                silent=8192,
                is_grouped_id=131072,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "to_id" / self.peer_structures("to_id"),
            "from_id_adjusted"
            / If(
                this.from_id == 0,
                IfThenElse(
                    this.to_id.user_id != 0,
                    "from_id_adjusted" / this.to_id.user_id,
                    "from_id_adjusted" / this.to_id.channel_id * -1,
                ),
            ),
            "date" / self.ttimestamp_struct,
            "action" / self.message_action_structures("action"),
        )

    def message_layer68_struct(self):
        return Struct(
            "sname" / Computed("message_layer68"),
            "signature" / Hex(Const(0xC09BE45F, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                unread=1,
                out=2,
                forwarded=4,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                has_reply_markup=64,
                has_entities=128,
                has_from_id=256,
                has_media=512,
                has_views=1024,
                is_via_bot=2048,
                post=16384,
                is_edited=32768,
                silent=8192,
                with_my_score=1073741824,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "to_id" / self.peer_structures("to_id"),
            "from_id_adjusted"
            / If(
                this.from_id == 0,
                IfThenElse(
                    this.to_id.user_id != 0,
                    "from_id_adjusted" / this.to_id.user_id,
                    "from_id_adjusted" / this.to_id.channel_id * -1,
                ),
            ),
            "fwd_from"
            / If(this.flags.forwarded, self.message_fwd_header_structures("fwd_from")),
            "via_bot_id" / If(this.flags.is_via_bot, Int32ul),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / If(this.flags.has_media, self.message_media_structures("media")),
            # The following two fields are copied from media, ignored.
            "_media_ttl" / Computed("ignored"),
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(
                this.flags.has_reply_markup,
                self.reply_markup_structures("reply_markup"),
            ),
            "entities"
            / If(
                this.flags.has_entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
            "views" / If(this.flags.has_views, Int32ul),
            "edit_timestamp" / If(this.flags.is_edited, Int32ul),
        )

    def message_old4_struct(self):
        return Struct(
            "sname" / Computed("message_old4"),
            "signature" / Hex(Const(0xC3060325, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                unread=1,
                out=2,
                forwarded=4,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                has_reply_markup=64,
                has_entities=128,
            ),
            "id" / Int32ul,
            "from_id" / Int32ul,
            "to_id" / self.peer_structures("to_id"),
            "fwd_from_id" / If(this.flags.forwarded, "fwd_from_id" / Int32ul),
            "fwd_from_timestamp"
            / If(this.flags.forwarded, "fwd_from_timestamp" / self.ttimestamp_struct),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / self.message_media_structures("media"),
            # The following field is copied from media, ignored.
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(
                this.flags.has_reply_markup,
                self.reply_markup_structures("reply_markup"),
            ),
            "entities"
            / If(
                this.flags.has_entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
        )

    def message_old5_struct(self):
        return Struct(
            "sname" / Computed("message_old5"),
            "signature" / Hex(Const(0xF07814C8, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                unread=1,
                out=2,
                forwarded=4,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                has_reply_markup=64,
                has_entities=128,
            ),
            "id" / Int32ul,
            "from_id" / Int32ul,
            "to_id" / self.peer_structures("to_id"),
            "fwd_from_id" / If(this.flags.forwarded, "fwd_from_id" / Int32ul),
            "fwd_from_timestamp"
            / If(this.flags.forwarded, "fwd_from_timestamp" / self.ttimestamp_struct),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / If(this.flags.has_media, self.message_media_structures("media")),
            # Thee following two fields are copied from media, ignored.
            "_media_ttl" / Computed("ignored"),
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(
                this.flags.has_reply_markup,
                self.reply_markup_structures("reply_markup"),
            ),
            "entities"
            / If(
                this.flags.has_entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
            "views" / If(this.flags.has_views, Int32ul),
            "edit_timestamp" / If(this.flags.is_edited, Int32ul),
        )

    def message_layer104_struct(self):
        return Struct(
            "sname" / Computed("message_layer104"),
            "signature" / Hex(Const(0x44F9B43D, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                out=2,
                forwarded=4,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                has_reply_markup=64,
                has_entities=128,
                has_from_id=256,
                has_media=512,
                has_views=1024,
                is_via_bot=2048,
                silent=8192,
                post=16384,
                is_edited=32768,
                has_author=65536,
                is_grouped_id=131072,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "to_id" / self.peer_structures("to_id"),
            "fwd_from"
            / If(this.flags.forwarded, self.message_fwd_header_structures("fwd_from")),
            "via_bot_id" / If(this.flags.is_via_bot, Int32ul),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / If(this.flags.has_media, self.message_media_structures("media")),
            # The following two fields are copied from media, ignored.
            "_media_ttl" / Computed("ignored"),
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(
                this.flags.has_reply_markup,
                self.reply_markup_structures("reply_markup"),
            ),
            "entities"
            / If(
                this.flags.has_entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
            "views" / If(this.flags.has_views, Int32ul),
            "edit_timestamp" / If(this.flags.is_edited, Int32ul),
            "post_author" / If(this.flags.has_author, self.tstring_struct),
            "grouped_id" / If(this.flags.is_grouped_id, Int64ul),
            "UNPARSED" / GreedyBytes,
        )

    def message_layer104_2_struct(self):
        return Struct(
            "sname" / Computed("message_layer104_2"),
            "signature" / Hex(Const(0x1C9B1027, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                out=2,
                forwarded=4,
                reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                reply_markup=64,
                entities=128,
                media=512,
                views=1024,
                via_bot=2048,
                silent=8192,
                post=16384,
                edited=32768,
                author=65536,
                grouped_id=131072,
                from_scheduled=262144,
                legacy=524288,
                reactions=1048576,
                edit_hide=2097152,
                restricted=4194304,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.from_id, Int32ul),
            "to_id" / self.peer_structures("to_id"),
            "fwd_from"
            / If(this.flags.forwarded, self.message_fwd_header_structures("fwd_from")),
            "via_bot_id" / If(this.flags.via_bot, Int32ul),
            "reply_to_msg_id" / If(this.flags.reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / If(this.flags.media, self.message_media_structures("media")),
            "_media_ttl" / Computed("ignored"),
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(this.flags.reply_markup, self.reply_markup_structures("reply_markup")),
            "entities"
            / If(
                this.flags.entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
            "views" / If(this.flags.views, Int32ul),
            "edit_timestamp" / If(this.flags.is_edited, self.ttimestamp_struct),
            "post_author" / If(this.flags.author, self.tstring_struct),
            "grouped_id" / If(this.flags.grouped_id, Int64ul),
            "reactions" / If(this.flags.reactions, self.message_reactions_struct()),
            "restricted" / If(this.flags.restricted, self.tstring_struct),
            "UNPARSED" / GreedyBytes,
        )

    def message_layer104_3_struct(self):
        return Struct(
            "sname" / Computed("message_layer104_3"),
            "signature" / Hex(Const(0x9789DAC4, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                out=2,
                forwarded=4,
                reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                reply_markup=64,
                entities=128,
                media=512,
                views=1024,
                via_bot=2048,
                silent=8192,
                post=16384,
                edited=32768,
                author=65536,
                grouped_id=131072,
                from_scheduled=262144,
                legacy=524288,
                reactions=1048576,
                edit_hide=2097152,
                restricted=4194304,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.from_id, Int32ul),
            "to_id" / self.peer_structures("to_id"),
            "fwd_from"
            / If(this.flags.forwarded, self.message_fwd_header_structures("fwd_from")),
            "via_bot_id" / If(this.flags.via_bot, Int32ul),
            "reply_to_msg_id" / If(this.flags.reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / If(this.flags.media, self.message_media_structures("media")),
            "_media_ttl" / Computed("ignored"),
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(this.flags.reply_markup, self.reply_markup_structures("reply_markup")),
            "entities"
            / If(
                this.flags.entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
            "views" / If(this.flags.views, Int32ul),
            "edit_timestamp" / If(this.flags.is_edited, self.ttimestamp_struct),
            "post_author" / If(this.flags.author, self.tstring_struct),
            "grouped_id" / If(this.flags.grouped_id, Int64ul),
            "reactions" / If(this.flags.reactions, self.message_reactions_struct()),
            "restricted"
            / If(
                this.flags.restricted,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "restricted_reasons_num" / Int32ul,
                    "restricted_reasons_array"
                    / Array(
                        this.restricted_reasons_num, self.restriction_reason_struct()
                    ),
                ),
            ),
            "UNPARSED" / GreedyBytes,
        )

    def message_struct(self):
        return Struct(
            "sname" / Computed("message_struct"),
            "signature" / Hex(Const(0x452C0E65, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                out=2,
                forwarded=4,
                is_reply_to_msg_id=8,
                mentioned=16,
                media_unread=32,
                has_reply_markup=64,
                has_entities=128,
                has_from_id=256,
                has_media=512,
                has_views=1024,
                is_via_bot=2048,
                silent=8192,
                post=16384,
                is_edited=32768,
                has_author=65536,
                is_grouped_id=131072,
                is_from_scheduled=262144,
                is_restricted=4194304,
                is_legacy=524288,
                is_edit_hide=2097152,
            ),
            "id" / Int32ul,
            "from_id" / If(this.flags.has_from_id, Int32ul),
            "to_id" / self.peer_structures("to_id"),
            "fwd_from"
            / If(this.flags.forwarded, self.message_fwd_header_structures("fwd_from")),
            "via_bot_id" / If(this.flags.is_via_bot, Int32ul),
            "reply_to_msg_id" / If(this.flags.is_reply_to_msg_id, Int32ul),
            "date" / self.ttimestamp_struct,
            "message" / self.tstring_struct,
            "media" / If(this.flags.has_media, self.message_media_structures("media")),
            # The following two fields are copied from media, ignored.
            "_media_ttl" / Computed("ignored"),
            "_media_caption_legacy" / Computed("ignored"),
            "reply_markup"
            / If(
                this.flags.has_reply_markup,
                self.reply_markup_structures("reply_markup"),
            ),
            "entities"
            / If(
                this.flags.has_entities,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "message_entity_num" / Int32ul,
                    "message_entity_array"
                    / Array(
                        this.message_entity_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
            "views" / If(this.flags.has_views, Int32ul),
            "edit_timestamp" / If(this.flags.is_edited, self.ttimestamp_struct),
            "post_author" / If(this.flags.has_author, self.tstring_struct),
            "grouped_id" / If(this.flags.is_grouped_id, Int64ul),
            "restriction_reasons"
            / If(
                this.flags.is_restricted,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "restriction_reasons_num" / Int32ul,
                    "restriction_reasons_array"
                    / Array(
                        this.restriction_reasons_num, self.restriction_reason_struct()
                    ),
                ),
            ),
            "UNPARSED" / GreedyBytes,
        )

    def message_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x452C0E65: LazyBound(lambda: self.message_struct()),
            0x44F9B43D: LazyBound(lambda: self.message_layer104_struct()),
            0x1C9B1027: LazyBound(lambda: self.message_layer104_2_struct()),
            0x9789DAC4: LazyBound(lambda: self.message_layer104_3_struct()),
            0x83E5DE54: LazyBound(lambda: self.message_empty_struct()),
            0x90DDDC11: LazyBound(lambda: self.message_layer72_struct()),
            0x9E19A1F6: LazyBound(lambda: self.message_service_struct()),
            0x9F8D60BB: LazyBound(lambda: self.message_service_old_struct()),
            0x05F46804: LazyBound(lambda: self.message_forwarded_old_struct()),
            0xA367E716: LazyBound(lambda: self.message_forwarded_old2_struct()),
            0xC06B9607: LazyBound(lambda: self.message_service_layer48_struct()),
            0xC09BE45F: LazyBound(lambda: self.message_layer68_struct()),
            0xA7AB1991: LazyBound(lambda: self.message_old3_struct()),
            0xC3060325: LazyBound(lambda: self.message_old4_struct()),
            0xF07814C8: LazyBound(lambda: self.message_old5_struct()),
            0x555555FA: LazyBound(lambda: self.message_secret_struct()),
        }
        return "message_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    """
    TODO not yet implemented

    case -260565816: result = new TL_message_old5();
    case 495384334: result = new TL_messageService_old2();
    case 585853626: result = new TL_message_old();
    case 736885382: result = new TL_message_old6();
    case 1431655928: result = new TL_message_secret_old();
    case 1431655929: result = new TL_message_secret_layer72();
    case 1450613171: result = new TL_message_old2();
    case 1537633299: result = new TL_message_old7();
    case -913120932: result = new TL_message_layer47();
    """

    # --------------------------------------------------------------------------

    def page_caption_struct(self):
        return Struct(
            "sname" / Computed("page_caption"),
            "signature" / Hex(Const(0x6F747657, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "credit" / self.rich_text_structures("credit"),
        )

    # --------------------------------------------------------------------------

    def page_list_ordered_item_blocks_struct(self):
        return Struct(
            "sname" / Computed("page_list_ordered_item_blocks"),
            "signature" / Hex(Const(0x98DD8936, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_block")),
        )

    def page_list_ordered_item_text_struct(self):
        return Struct(
            "sname" / Computed("page_list_ordered_item_text"),
            "signature" / Hex(Const(0x5E068047, Int32ul)),
            "num" / self.tstring_struct,
            "text" / self.rich_text_structures("text"),
        )

    def page_list_ordered_item_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x98DD8936: LazyBound(lambda: self.page_list_ordered_item_blocks_struct()),
            0x5E068047: LazyBound(lambda: self.page_list_ordered_item_text_struct()),
        }
        return "page_list_ordered_item_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def page_block_audio_struct(self):
        return Struct(
            "sname" / Computed("page_block_audio"),
            "signature" / Hex(Const(0x804361EA, Int32ul)),
            "audio_id" / Int64ul,
            "caption" / self.page_caption_struct(),
        )

    def page_block_subtitle_struct(self):
        return Struct(
            "sname" / Computed("page_block_subtitle"),
            "signature" / Hex(Const(0x8FFA9A1F, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_block_ordered_list_struct(self):
        return Struct(
            "sname" / Computed("page_block_ordered_list"),
            "signature" / Hex(Const(0x9A8AE1E1, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_list_oitems_num" / Int32ul,
            "page_list_oitems"
            / Array(
                this.page_list_oitems_num,
                self.page_list_ordered_item_structures("page_list"),
            ),
        )

    def page_block_map_struct(self):
        return Struct(
            "sname" / Computed("page_block_map"),
            "signature" / Hex(Const(0xA44F3EF6, Int32ul)),
            "geo" / self.geo_point_structures("geo"),
            "zoom" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
            "caption" / self.page_caption_struct(),
        )

    def page_block_embed_struct(self):
        return Struct(
            "sname" / Computed("page_block_embed"),
            "signature" / Hex(Const(0xA8718DC5, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                full_width=1,
                has_url=2,
                has_html=4,
                allow_scrolling=8,
                has_poster_photo_id=16,
                has_dimensions=32,
            ),
            "url" / If(this.flags.has_url, self.tstring_struct),
            "html" / If(this.flags.has_html, self.tstring_struct),
            "poster_photo_id" / If(this.flags.has_poster_photo_id, Int64ul),
            "w" / If(this.flags.has_dimensions, Int32ul),
            "h" / If(this.flags.has_dimensions, Int32ul),
            "caption" / self.page_caption_struct(),
        )

    def page_block_author_date_struct(self):
        return Struct(
            "sname" / Computed("page_block_author_date"),
            "signature" / Hex(Const(0xBAAFE5E0, Int32ul)),
            "author" / self.rich_text_structures("author"),
            "published_timestamp" / Int32ul,
        )

    def page_block_table_struct(self):
        return Struct(
            "sname" / Computed("page_block_table"),
            "signature" / Hex(Const(0xBF4DEA82, Int32ul)),
            "flags" / FlagsEnum(Int32ul, bordered=1, striped=2),
            "title" / self.rich_text_structures("title"),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_table_row_num" / Int32ul,
            "page_table_row_array"
            / Array(this.page_table_row_num, self.page_table_row_struct()),
        )

    def page_block_header_struct(self):
        return Struct(
            "sname" / Computed("page_block_header"),
            "signature" / Hex(Const(0xBFD064EC, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_block_preformatted_struct(self):
        return Struct(
            "sname" / Computed("page_block_preformatted"),
            "signature" / Hex(Const(0xC070D93E, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "language" / self.tstring_struct,
        )

    def page_block_embed_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_embed_layer82"),
            "signature" / Hex(Const(0xCDE200D1, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                full_width=1,
                has_url=2,
                has_html=4,
                allow_scrolling=8,
                has_poster_photo_id=16,
            ),
            "url" / If(this.flags.has_url, self.tstring_struct),
            "html" / If(this.flags.has_html, self.tstring_struct),
            "poster_photo_id" / If(this.flags.has_poster_photo_id, Int64ul),
            "w" / Int32ul,
            "h" / Int32ul,
            "caption" / self.rich_text_structures("caption"),
        )

    def page_block_anchor_struct(self):
        return Struct(
            "sname" / Computed("page_block_anchor"),
            "signature" / Hex(Const(0xCE0D37B0, Int32ul)),
            "name" / self.tstring_struct,
        )

    def page_block_embed_layer60_struct(self):
        return Struct(
            "sname" / Computed("page_block_embed_layer60"),
            "signature" / Hex(Const(0xD935D8FB, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul, full_width=1, has_url=2, has_html=4, allow_scrolling=8
            ),
            "url" / If(this.flags.has_url, self.tstring_struct),
            "html" / If(this.flags.has_html, self.tstring_struct),
            "w" / Int32ul,
            "h" / Int32ul,
            "caption" / self.rich_text_structures("caption"),
        )

    def page_block_video_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_video_layer82"),
            "signature" / Hex(Const(0xD9D71866, Int32ul)),
            "flags" / FlagsEnum(Int32ul, autoplay=1, loop=2),
            "video_id" / Int64ul,
            "caption" / self.rich_text_structures("caption"),
        )

    def page_block_divider_struct(self):
        return Struct(
            "sname" / Computed("page_block_divider"),
            "signature" / Hex(Const(0xDB20B188, Int32ul)),
        )

    def page_block_list_struct(self):
        return Struct(
            "sname" / Computed("page_block_list"),
            "signature" / Hex(Const(0xE4E88011, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_list_item_num" / Int32ul,
            "page_list_item_array"
            / Array(
                this.page_list_item_num,
                self.page_list_item_structures("page_list_item"),
            ),
        )

    def page_block_photo_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_photo_layer82"),
            "signature" / Hex(Const(0xE9C69982, Int32ul)),
            "photo_id" / Int64ul,
            "caption" / self.rich_text_structures("caption"),
        )

    def page_block_channel_struct(self):
        return Struct(
            "sname" / Computed("page_block_channel"),
            "signature" / Hex(Const(0xEF1751B5, Int32ul)),
            "channel" / self.chat_structures("channel"),
        )

    def page_block_subheader_struct(self):
        return Struct(
            "sname" / Computed("page_block_subheader"),
            "signature" / Hex(Const(0xF12BB6E1, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_block_embed_post_struct(self):
        return Struct(
            "sname" / Computed("page_block_embed_post"),
            "signature" / Hex(Const(0xF259A80B, Int32ul)),
            "url" / self.tstring_struct,
            "webpage_id" / Int64ul,
            "author_photo_id" / Int64ul,
            "date" / self.ttimestamp_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_blocks_num" / Int32ul,
            "page_blocks_array"
            / Array(this.page_blocks_num, self.page_block_structures("page_block")),
            "caption" / self.page_caption_struct(),
        )

    def page_block_slideshow_struct(self):
        return Struct(
            "sname" / Computed("page_block_slideshow"),
            "signature" / Hex(Const(0x031F9590, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_blocks_num" / Int32ul,
            "page_blocks_array"
            / Array(this.page_blocks_num, self.page_block_structures("page_block")),
            "caption" / self.page_caption_struct(),
        )

    def page_block_collage_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_collage_layer82"),
            "signature" / Hex(Const(0x08B31C4F, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_blocks_num" / Int32ul,
            "page_blocks_array"
            / Array(this.page_blocks_num, self.page_block_structures("page_block")),
            "caption_text" / self.rich_text_structures("caption_text"),
        )

    def page_block_slideshow_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_slideshow_layer82"),
            "signature" / Hex(Const(0x130C8963, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_blocks_num" / Int32ul,
            "page_blocks_array"
            / Array(this.page_blocks_num, self.page_block_structures("page_block")),
            "caption_text" / self.rich_text_structures("caption_text"),
        )

    def page_block_unsupported_struct(self):
        return Struct(
            "sname" / Computed("page_block_unsupported"),
            "signature" / Hex(Const(0x13567E8A, Int32ul)),
        )

    def page_block_related_articles_struct(self):
        return Struct(
            "sname" / Computed("page_block_related_articles"),
            "signature" / Hex(Const(0x16115A96, Int32ul)),
            "title" / self.rich_text_structures("title"),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_related_articles_num" / Int32ul,
            "page_related_articles_array"
            / Array(this.page_related_articles_num, self.page_related_article_struct()),
        )

    def page_block_photo_struct(self):
        return Struct(
            "sname" / Computed("page_block_photo"),
            "signature" / Hex(Const(0x1759C560, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_url=1),
            "photo_id" / Int64ul,
            "caption" / self.page_caption_struct(),
            "url" / If(this.flags.has_url, self.tstring_struct),
            "webpage_id" / If(this.flags.has_url, Int64ul),
        )

    def page_block_kicker_struct(self):
        return Struct(
            "sname" / Computed("page_block_kicker"),
            "signature" / Hex(Const(0x1E148390, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_block_blockquote_struct(self):
        return Struct(
            "sname" / Computed("page_block_blockquote"),
            "signature" / Hex(Const(0x263D7C26, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "caption" / self.rich_text_structures("caption"),
        )

    def page_block_embed_post_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_embed_post_layer82"),
            "signature" / Hex(Const(0x292C7BE9, Int32ul)),
            "url" / self.tstring_struct,
            "webpage_id" / Int64ul,
            "author_photo_id" / Int64ul,
            "author" / self.tstring_struct,
            "date" / self.ttimestamp_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_blocks_num" / Int32ul,
            "page_blocks_array"
            / Array(this.page_blocks_num, self.page_block_structures("page_block")),
            "caption_text" / self.rich_text_structures("caption_text"),
        )

    def page_block_audio_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_audio_layer82"),
            "signature" / Hex(Const(0x31B81A7F, Int32ul)),
            "audio_id" / Int64ul,
            "caption_text" / self.rich_text_structures("caption_text"),
        )

    def page_block_cover_struct(self):
        return Struct(
            "sname" / Computed("page_block_cover"),
            "signature" / Hex(Const(0x39F23300, Int32ul)),
            "cover" / self.page_block_structures("cover"),
        )

    def page_block_list_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_block_list_layer82"),
            "signature" / Hex(Const(0x3A58C7F4, Int32ul)),
            "ordered" / self.tbool_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "rich_text_num" / Int32ul,
            "rich_text_array"
            / Array(this.rich_text_num, self.rich_text_structures("rich_text")),
        )

    def page_block_author_date_layer60_struct(self):
        return Struct(
            "sname" / Computed("page_block_author_date_layer60"),
            "signature" / Hex(Const(0x3D5B64F2, Int32ul)),
            "author_string" / self.tstring_struct,
            "published_timestamp" / Int32ul,
        )

    def page_block_paragraph_struct(self):
        return Struct(
            "sname" / Computed("page_block_paragraph"),
            "signature" / Hex(Const(0x467A0766, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_block_footer_struct(self):
        return Struct(
            "sname" / Computed("page_block_footer"),
            "signature" / Hex(Const(0x48870999, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_block_pullquote_struct(self):
        return Struct(
            "sname" / Computed("page_block_pullquote"),
            "signature" / Hex(Const(0x4F4456D3, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "caption" / self.rich_text_structures("caption"),
        )

    def page_block_collage_struct(self):
        return Struct(
            "sname" / Computed("page_block_collage"),
            "signature" / Hex(Const(0x65A0FA4D, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_blocks_num" / Int32ul,
            "page_blocks_array"
            / Array(this.page_blocks_num, self.page_block_structures("page_block")),
            "caption" / self.page_caption_struct(),
        )

    def page_block_title_struct(self):
        return Struct(
            "sname" / Computed("page_block_title"),
            "signature" / Hex(Const(0x70ABC3FD, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_block_details_struct(self):
        return Struct(
            "sname" / Computed("page_block_details"),
            "signature" / Hex(Const(0x76768BED, Int32ul)),
            "flags" / FlagsEnum(Int32ul, is_open=1),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_blocks_num" / Int32ul,
            "page_blocks_array"
            / Array(this.page_blocks_num, self.page_block_structures("page_block")),
            "title" / self.rich_text_structures("title"),
        )

    def page_block_video_struct(self):
        return Struct(
            "sname" / Computed("page_block_video"),
            "signature" / Hex(Const(0x7C8FE7B6, Int32ul)),
            "flags" / FlagsEnum(Int32ul, autoplay=1, loop=2),
            "video_id" / Int64ul,
            "caption" / self.page_caption_struct(),
        )

    def page_block_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x804361EA: LazyBound(lambda: self.page_block_audio_struct()),
            0x8FFA9A1F: LazyBound(lambda: self.page_block_subtitle_struct()),
            0x9A8AE1E1: LazyBound(lambda: self.page_block_ordered_list_struct()),
            0xA44F3EF6: LazyBound(lambda: self.page_block_map_struct()),
            0xA8718DC5: LazyBound(lambda: self.page_block_embed_struct()),
            0xBAAFE5E0: LazyBound(lambda: self.page_block_author_date_struct()),
            0xBF4DEA82: LazyBound(lambda: self.page_block_table_struct()),
            0xBFD064EC: LazyBound(lambda: self.page_block_header_struct()),
            0xC070D93E: LazyBound(lambda: self.page_block_preformatted_struct()),
            0xCDE200D1: LazyBound(lambda: self.page_block_embed_layer82_struct()),
            0xCE0D37B0: LazyBound(lambda: self.page_block_anchor_struct()),
            0xD935D8FB: LazyBound(lambda: self.page_block_embed_layer60_struct()),
            0xD9D71866: LazyBound(lambda: self.page_block_video_layer82_struct()),
            0xDB20B188: LazyBound(lambda: self.page_block_divider_struct()),
            0xE4E88011: LazyBound(lambda: self.page_block_list_struct()),
            0xE9C69982: LazyBound(lambda: self.page_block_photo_layer82_struct()),
            0xEF1751B5: LazyBound(lambda: self.page_block_channel_struct()),
            0xF12BB6E1: LazyBound(lambda: self.page_block_subheader_struct()),
            0xF259A80B: LazyBound(lambda: self.page_block_embed_post_struct()),
            0x031F9590: LazyBound(lambda: self.page_block_slideshow_struct()),
            0x08B31C4F: LazyBound(lambda: self.page_block_collage_layer82_struct()),
            0x130C8963: LazyBound(lambda: self.page_block_slideshow_layer82_struct()),
            0x13567E8A: LazyBound(lambda: self.page_block_unsupported_struct()),
            0x16115A96: LazyBound(lambda: self.page_block_related_articles_struct()),
            0x1759C560: LazyBound(lambda: self.page_block_photo_struct()),
            0x1E148390: LazyBound(lambda: self.page_block_kicker_struct()),
            0x263D7C26: LazyBound(lambda: self.page_block_blockquote_struct()),
            0x292C7BE9: LazyBound(lambda: self.page_block_embed_post_layer82_struct()),
            0x31B81A7F: LazyBound(lambda: self.page_block_audio_layer82_struct()),
            0x39F23300: LazyBound(lambda: self.page_block_cover_struct()),
            0x3A58C7F4: LazyBound(lambda: self.page_block_list_layer82_struct()),
            0x3D5B64F2: LazyBound(lambda: self.page_block_author_date_layer60_struct()),
            0x467A0766: LazyBound(lambda: self.page_block_paragraph_struct()),
            0x48870999: LazyBound(lambda: self.page_block_footer_struct()),
            0x4F4456D3: LazyBound(lambda: self.page_block_pullquote_struct()),
            0x65A0FA4D: LazyBound(lambda: self.page_block_collage_struct()),
            0x70ABC3FD: LazyBound(lambda: self.page_block_title_struct()),
            0x76768BED: LazyBound(lambda: self.page_block_details_struct()),
            0x7C8FE7B6: LazyBound(lambda: self.page_block_video_struct()),
        }
        return "page_block_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def page_part_layer67_struct(self):
        return Struct(
            "sname" / Computed("page_part_layer67"),
            "signature" / Hex(Const(0x8DEE6C44, Int32ul)),
            "vector_sig_page_block" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_block")),
            "vector_sig_photo" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_num" / Int32ul,
            "photo_array" / Array(this.photo_num, self.photo_structures("photo")),
            "vector_sig_document" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_num" / Int32ul,
            "document_array"
            / Array(this.document_num, self.document_structures("document")),
        )

    def page_full_layer67_struct(self):
        return Struct(
            "sname" / Computed("page_full_layer67"),
            "signature" / Hex(Const(0xD7A19D69, Int32ul)),
            "vector_sig_page_block" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_block")),
            "vector_sig_photo" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_num" / Int32ul,
            "photo_array" / Array(this.photo_num, self.photo_structures("photo")),
            "vector_sig_document" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_num" / Int32ul,
            "document_array"
            / Array(this.document_num, self.document_structures("document")),
        )

    def page_part_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_part_layer82"),
            "signature" / Hex(Const(0x8E3F9EBE, Int32ul)),
            "vector_sig_page_block" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_block")),
            "vector_sig_photo" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_num" / Int32ul,
            "photo_array" / Array(this.photo_num, self.photo_structures("photo")),
            "vector_sig_document" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_num" / Int32ul,
            "document_array"
            / Array(this.document_num, self.document_structures("document")),
        )

    def page_full_layer82_struct(self):
        return Struct(
            "sname" / Computed("page_full_layer82"),
            "signature" / Hex(Const(0x556EC7AA, Int32ul)),
            "vector_sig_page_block" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_block")),
            "vector_sig_photo" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_num" / Int32ul,
            "photo_array" / Array(this.photo_num, self.photo_structures("photo")),
            "vector_sig_document" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_num" / Int32ul,
            "document_array"
            / Array(this.document_num, self.document_structures("document")),
        )

    def page_layer110_struct(self):
        return Struct(
            "sname" / Computed("page_layer110"),
            "signature" / Hex(Const(0xAE891BEC, Int32ul)),
            "flags" / FlagsEnum(Int32ul, part=1, rtl=2),
            "url" / self.tstring_struct,
            "vector_sig_page_block" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_block")),
            "vector_sig_photo" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_num" / Int32ul,
            "photo_array" / Array(this.photo_num, self.photo_structures("photo")),
            "vector_sig_document" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_num" / Int32ul,
            "document_array"
            / Array(this.document_num, self.document_structures("document")),
        )

    def page_struct(self):
        return Struct(
            "sname" / Computed("page"),
            "signature" / Hex(Const(0x98657F0D, Int32ul)),
            "flags" / FlagsEnum(Int32ul, part=1, rtl=2, v2=4, has_views=8),
            "url" / self.tstring_struct,
            "vector_sig_page_block" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_block")),
            "vector_sig_photo" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_num" / Int32ul,
            "photo_array" / Array(this.photo_num, self.photo_structures("photo")),
            "vector_sig_document" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_num" / Int32ul,
            "document_array"
            / Array(this.document_num, self.document_structures("document")),
            "views" / If(this.flags.has_views, Int32ul),
        )

    def page_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x98657F0D: LazyBound(lambda: self.page_struct()),
            0x8DEE6C44: LazyBound(lambda: self.page_part_layer67_struct()),
            0x8E3F9EBE: LazyBound(lambda: self.page_part_layer82_struct()),
            0xAE891BEC: LazyBound(lambda: self.page_layer110_struct()),
            0xD7A19D69: LazyBound(lambda: self.page_full_layer67_struct()),
            0x556EC7AA: LazyBound(lambda: self.page_full_layer82_struct()),
        }
        return "page_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def page_list_item_text_struct(self):
        return Struct(
            "sname" / Computed("page_list_item_text"),
            "signature" / Hex(Const(0xB92FB6CD, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def page_list_item_blocks_struct(self):
        return Struct(
            "sname" / Computed("page_list_item_blocks"),
            "signature" / Hex(Const(0x25E073FC, Int32ul)),
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_block_num" / Int32ul,
            "page_block_array"
            / Array(this.page_block_num, self.page_block_structures("page_table_cell")),
        )

    def page_list_item_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xB92FB6CD: LazyBound(lambda: self.page_list_item_text_struct()),
            0x25E073FC: LazyBound(lambda: self.page_list_item_blocks_struct()),
        }
        return "page_list_item_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def page_related_article_struct(self):
        return Struct(
            "sname" / Computed("page_related_article"),
            "signature" / Hex(Const(0xB390DC08, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_title=1,
                has_description=2,
                has_photo=4,
                has_author=8,
                has_published_timestamp=16,
            ),
            "url" / self.tstring_struct,
            "webpage_id" / Int64ul,
            "title" / If(this.flags.has_title, self.tstring_struct),
            "description" / If(this.flags.has_description, self.tstring_struct),
            "photo_id" / If(this.flags.has_photo, Int64ul),
            "author" / If(this.flags.has_author, self.tstring_struct),
            "published_timestamp" / If(this.flags.has_published_timestamp, Int32ul),
        )

    # --------------------------------------------------------------------------

    def page_table_cell_struct(self):
        return Struct(
            "sname" / Computed("page_table_cell"),
            "signature" / Hex(Const(0x34566B6A, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                header=1,
                has_colspan=2,
                has_rowspan=4,
                align_center=8,
                align_right=16,
                valign_middle=32,
                valign_bottom=64,
                has_text=128,
            ),
            "text" / If(this.flags.has_text, self.rich_text_structures("text")),
            "colspan" / If(this.flags.has_colspan, Int32ul),
            "rowspan" / If(this.flags.has_rowspan, Int32ul),
        )

    def page_table_row_struct(self):
        return Struct(
            "sname" / Computed("page_table_row"),
            "signature" / Hex(Const(0xE0C0C5E5, Int32ul)),
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "page_table_cell_num" / Int32ul,
            "page_table_cell_array"
            / Array(this.page_table_cell_num, self.page_table_cell_struct()),
        )

    # --------------------------------------------------------------------------

    def peer_channel_struct(self):
        return Struct(
            "sname" / Computed("peer_channel"),
            "signature" / Hex(Const(0xBDDDE532, Int32ul)),
            "channel_id" / Int32ul,
        )

    def peer_chat_struct(self):
        return Struct(
            "sname" / Computed("peer_chat"),
            "signature" / Hex(Const(0xBAD0E5BB, Int32ul)),
            "chat_id" / Int32ul,
        )

    def peer_user_struct(self):
        return Struct(
            "sname" / Computed("peer_user"),
            "signature" / Hex(Const(0x9DB1BC6D, Int32ul)),
            "user_id" / Int32ul,
        )

    def peer_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xBDDDE532: LazyBound(lambda: self.peer_channel_struct()),
            0xBAD0E5BB: LazyBound(lambda: self.peer_chat_struct()),
            0x9DB1BC6D: LazyBound(lambda: self.peer_user_struct()),
        }
        return "peer_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def peer_notify_settings_layer47_struct(self):
        return Struct(
            "sname" / Computed("peer_notify_settings_layer47"),
            "signature" / Hex(Const(0x8D5E11EE, Int32ul)),
            "mute_until" / Int32ul,
            "sound" / self.tstring_struct,
            "show_previews" / self.tbool_struct,
            "event_mask" / Int32ul,
        )

    def peer_notify_settings_layer77_struct(self):
        return Struct(
            "sname" / Computed("peer_notify_settings_layer77"),
            "signature" / Hex(Const(0x9ACDA4C0, Int32ul)),
            "flags" / FlagsEnum(Int32ul, show_previews=1, is_silent=2),
            "mute_until" / Int32ul,
            "sound" / self.tstring_struct,
        )

    def peer_notify_settings_struct(self):
        return Struct(
            "sname" / Computed("peer_notify_settings"),
            "signature" / Hex(Const(0xAF509D20, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_show_previews=1,
                has_silent=2,
                has_mute_until=4,
                has_sound=8,
            ),
            "show_previews" / If(this.flags.has_show_previews, self.tbool_struct),
            "silent" / If(this.flags.has_silent, self.tbool_struct),
            "mute_until" / If(this.flags.has_mute_until, Int32ul),
            "sound" / If(this.flags.has_sound, self.tstring_struct),
        )

    def peer_notify_settings_empty_layer77_struct(self):
        return Struct(
            "sname" / Computed("peer_notify_settings_empty_layer77"),
            "signature" / Hex(Const(0x70A68512, Int32ul)),
        )

    def peer_notify_settings_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x8D5E11EE: LazyBound(lambda: self.peer_notify_settings_layer47_struct()),
            0x9ACDA4C0: LazyBound(lambda: self.peer_notify_settings_layer77_struct()),
            0xAF509D20: LazyBound(lambda: self.peer_notify_settings_struct()),
            0x70A68512: LazyBound(
                lambda: self.peer_notify_settings_empty_layer77_struct()
            ),
        }
        return "peer_notify_settings_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def peer_settings_v_5_15_0_struct(self):
        return Struct(
            "sname" / Computed("peer_settings_v_5_15_0"),
            "signature" / Hex(Const(0x818426CD, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                report_spam=1,
                add_contact=2,
                block_contact=4,
                share_contact=8,
                need_contacts_exception=16,
                report_geo=32,
            ),
        )

    def peer_settings_struct(self):
        return Struct(
            "sname" / Computed("peer_settings"),
            "signature" / Hex(Const(0x733F2961, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                report_spam=1,
                add_contact=2,
                block_contact=4,
                share_contact=8,
                need_contacts_exception=16,
                report_geo=32,
                has_geo_distance=64,
                autoarchived=128,
            ),
            "geo_distance" / If(this.flags.has_geo_distance, Int32ul),
        )

    def peer_settings_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x818426CD: LazyBound(lambda: self.peer_settings_v_5_15_0_struct()),
            0x733F2961: LazyBound(lambda: self.peer_settings_struct()),
        }
        return "peer_settings_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def phone_call_discard_reason_missed_struct(self):
        return Struct(
            "sname" / Computed("phone_call_discard_reason_missed"),
            "signature" / Hex(Const(0x85E42301, Int32ul)),
        )

    def phone_call_discard_reason_busy_struct(self):
        return Struct(
            "sname" / Computed("phone_call_discard_reason_busy"),
            "signature" / Hex(Const(0xFAF7E8C9, Int32ul)),
        )

    def phone_call_discard_reason_hangup_struct(self):
        return Struct(
            "sname" / Computed("phone_call_discard_reason_hangup"),
            "signature" / Hex(Const(0x57ADC690, Int32ul)),
        )

    def phone_call_discard_reason_disconnect_struct(self):
        return Struct(
            "sname" / Computed("phone_call_discard_reason_disconnect"),
            "signature" / Hex(Const(0xE095C1A0, Int32ul)),
        )

    def phone_call_discard_reason_allow_group_call_struct(self):
        return Struct(
            "sname" / Computed("phone_call_discard_reason_allow_group_call"),
            "signature" / Hex(Const(0xAFE2B839, Int32ul)),
            "encrypted_key" / self.tbytes_struct,
        )

    def phone_call_discarded_struct(self):
        return Struct(
            "sname" / Computed("phone_call_discarded"),
            "signature" / Hex(Const(0x50CA4DE1, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                is_discarded=1,
                has_duration=2,
                need_rating=4,
                need_debug=8,
                is_video=32,
            ),
            "id" / Int64ul,
            "discard_reason"
            / If(
                this.flags.is_discarded,
                self.phone_call_discard_reason_structures("discard_reason"),
            ),
            "duration" / If(this.flags.has_duration, Int32ul),
        )

    def phone_call_discard_reason_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x85E42301: LazyBound(
                lambda: self.phone_call_discard_reason_missed_struct()
            ),
            0xAFE2B839: LazyBound(
                lambda: self.phone_call_discard_reason_allow_group_call_struct()
            ),
            0xE095C1A0: LazyBound(
                lambda: self.phone_call_discard_reason_disconnect_struct()
            ),
            0xFAF7E8C9: LazyBound(lambda: self.phone_call_discard_reason_busy_struct()),
            0x57ADC690: LazyBound(
                lambda: self.phone_call_discard_reason_hangup_struct()
            ),
        }
        return "phone_call_discard_reason_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def photo_size_empty_struct(self):
        return Struct(
            "sname" / Computed("photo_size_empty"),
            "signature" / Hex(Const(0x0E17E23C, Int32ul)),
            "type" / self.tstring_struct,
        )

    def photo_size_struct(self):
        return Struct(
            "sname" / Computed("photo_size"),
            "signature" / Hex(Const(0x77BFB61B, Int32ul)),
            "type" / self.tstring_struct,
            "file_location" / self.file_location_structures("file_location"),
            "w" / Int32ul,
            "h" / Int32ul,
            "size" / Int32ul,
        )

    def photo_stripped_size_struct(self):
        return Struct(
            "sname" / Computed("photo_stripped_size"),
            "signature" / Hex(Const(0xE0B0BC2E, Int32ul)),
            "type" / self.tstring_struct,
            "bytes" / self.tbytes_struct,
            "h" / Computed(50),
            "w" / Computed(50),
        )

    def photo_cached_size_struct(self):
        return Struct(
            "sname" / Computed("photo_cached_size"),
            "signature" / Hex(Const(0xE9A734FA, Int32ul)),
            "type" / self.tstring_struct,
            "location" / self.file_location_structures("location"),
            "w" / Int32ul,
            "h" / Int32ul,
            "bytes" / self.tbytes_struct,
        )

    def photo_size_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x0E17E23C: LazyBound(lambda: self.photo_size_empty_struct()),
            0xE0B0BC2E: LazyBound(lambda: self.photo_stripped_size_struct()),
            0xE9A734FA: LazyBound(lambda: self.photo_cached_size_struct()),
            0x77BFB61B: LazyBound(lambda: self.photo_size_struct()),
        }
        return "photo_size_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def photo_empty_struct(self):
        return Struct(
            "sname" / Computed("photo_empty"),
            "signature" / Hex(Const(0x2331B22D, Int32ul)),
            "id" / Int64ul,
        )

    def photo_layer55_struct(self):
        return Struct(
            "sname" / Computed("photo_layer55"),
            "signature" / Hex(Const(0xCDED42FE, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_size_num" / Int32ul,
            "photo_size_array"
            / Array(this.photo_size_num, self.photo_size_structures("photo_size")),
        )

    def photo_layer82_struct(self):
        return Struct(
            "sname" / Computed("photo_layer82"),
            "signature" / Hex(Const(0x9288DD29, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_stickers=1),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_size_num" / Int32ul,
            "photo_size_array"
            / Array(this.photo_size_num, self.photo_size_structures("photo_size")),
        )

    def photo_old_struct(self):
        return Struct(
            "sname" / Computed("photo_old"),
            "signature" / Hex(Const(0x22B56751, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "caption" / self.tstring_struct,
            "geo" / self.geo_point_structures("geo"),
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_size_num" / Int32ul,
            "photo_size_array"
            / Array(this.photo_size_num, self.photo_size_structures("photo_size")),
        )

    def photo_old2_struct(self):
        return Struct(
            "sname" / Computed("photo_old2"),
            "signature" / Hex(Const(0xC3838076, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "geo" / self.geo_point_structures("geo"),
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_size_num" / Int32ul,
            "photo_size_array"
            / Array(this.photo_size_num, self.photo_size_structures("photo_size")),
        )

    def photo_layer97_struct(self):
        return Struct(
            "sname" / Computed("photo_layer97"),
            "signature" / Hex(Const(0x9C477DD8, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_stickers=1),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "file_reference" / self.tbytes_struct,
            "date" / self.ttimestamp_struct,
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_size_num" / Int32ul,
            "photo_size_array"
            / Array(this.photo_size_num, self.photo_size_structures("photo_size")),
        )

    def photo_layer115_struct(self):
        return Struct(
            "sname" / Computed("photo_layer115"),
            "signature" / Hex(Const(0xD07504A5, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_stickers=1),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "file_reference" / self.tbytes_struct,
            "date" / self.ttimestamp_struct,
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_size_num" / Int32ul,
            "photo_size_array"
            / Array(this.photo_size_num, self.photo_size_structures("photo_size")),
            "dc_id" / Int32ul,
        )

    def photo_struct(self):
        return Struct(
            "sname" / Computed("photo"),
            "signature" / Hex(Const(0xFB197A65, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_stickers=1, has_video_size=2),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "file_reference" / self.tbytes_struct,
            "date" / self.ttimestamp_struct,
            "vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "photo_size_num" / Int32ul,
            "photo_size_array"
            / Array(this.photo_size_num, self.photo_size_structures("photo_size")),
            "video_size"
            / If(
                this.flags.has_video_size,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "video_sizes_num" / Int32ul,
                    "video_sizes_array"
                    / Array(
                        this.video_sizes_num, self.video_size_structures("video_size")
                    ),
                ),
            ),
            "dc_id" / Int32ul,
        )

    def photo_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xFB197A65: LazyBound(lambda: self.photo_struct()),
            0xD07504A5: LazyBound(lambda: self.photo_layer115_struct()),
            0x9288DD29: LazyBound(lambda: self.photo_layer82_struct()),
            0x9C477DD8: LazyBound(lambda: self.photo_layer97_struct()),
            0xC3838076: LazyBound(lambda: self.photo_old2_struct()),
            0xCDED42FE: LazyBound(lambda: self.photo_layer55_struct()),
            0x22B56751: LazyBound(lambda: self.photo_old_struct()),
            0x2331B22D: LazyBound(lambda: self.photo_empty_struct()),
        }
        return "photo_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def poll_answer_struct(self):
        return Struct(
            "sname" / Computed("poll_answer"),
            "signature" / Hex(Const(0x6CA9C2E9, Int32ul)),
            "text" / self.tstring_struct,
            "option" / self.tbytes_struct,
        )

    def poll_answer_voters_struct(self):
        return Struct(
            "sname" / Computed("poll_answer_voters"),
            "signature" / Hex(Const(0x3B6DDAD2, Int32ul)),
            "flags" / FlagsEnum(Int32ul, is_chosen=1),
            "option" / self.tbytes_struct,
            "voters" / Int32ul,
        )

    # --------------------------------------------------------------------------

    def poll_layer111_struct(self):
        return Struct(
            "sname" / Computed("poll_layer111"),
            "signature" / Hex(Const(0xD5529D06, Int32ul)),
            "id" / Int64ul,
            "flags" / FlagsEnum(Int32ul, closed=1),
            "question" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "poll_answers_num" / Int32ul,
            "poll_answers_array"
            / Array(this.poll_answers_num, self.poll_answer_struct()),
        )

    def poll_struct(self):
        return Struct(
            "sname" / Computed("poll"),
            "signature" / Hex(Const(0x86E18161, Int32ul)),
            "id" / Int64ul,
            "flags"
            / FlagsEnum(
                Int32ul,
                closed=1,
                public_voters=2,
                multiple_choice=4,
                quiz=8,
                has_close_period=16,
                has_close_date=32,
            ),
            "question" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "poll_answers_num" / Int32ul,
            "poll_answers_array"
            / Array(this.poll_answers_num, self.poll_answer_struct()),
            "close_period" / If(this.flags.has_close_period, Int32ul),
            "close_date" / If(this.flags.has_close_date, self.ttimestamp_struct),
        )

    def poll_to_delete_struct(self):
        return Struct(
            "sname" / Computed("poll_to_delete"),
            "signature" / Hex(Const(0xAF746786, Int32ul)),
            "id" / Int64ul,
            "flags"
            / FlagsEnum(
                Int32ul,
                closed=1,
                public_voters=2,
                multiple_choice=4,
                quiz=8,
                has_close_date=16,
            ),
            "question" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "poll_answers_num" / Int32ul,
            "poll_answers_array"
            / Array(this.poll_answers_num, self.poll_answer_struct()),
            "close_date" / If(this.flags.has_close_date, self.ttimestamp_struct),
        )

    def poll_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x86E18161: LazyBound(lambda: self.poll_struct()),
            0xD5529D06: LazyBound(lambda: self.poll_layer111_struct()),
            0xAF746786: LazyBound(lambda: self.poll_to_delete_struct()),
        }
        return "poll_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def poll_results_layer108_struct(self):
        return Struct(
            "sname" / Computed("poll_results_layer108"),
            "signature" / Hex(Const(0x5755785A, Int32ul)),
            "flags" / FlagsEnum(Int32ul, min=1, voters=2, total=4),
            "poll_answer_voters"
            / If(
                this.flags.voters,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "poll_answer_voters_num" / Int32ul,
                    "poll_answer_voters_array"
                    / Array(
                        this.poll_answer_voters_num, self.poll_answer_voters_struct()
                    ),
                ),
            ),
            "total_voters" / If(this.flags.total, Int32ul),
        )

    def poll_results_layer111_struct(self):
        return Struct(
            "sname" / Computed("poll_results_layer111"),
            "signature" / Hex(Const(0xC87024A2, Int32ul)),
            "flags" / FlagsEnum(Int32ul, min=1, voters=2, total=4, recent_voters=8),
            "poll_answer_voters"
            / If(
                this.flags.voters,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "poll_answer_voters_num" / Int32ul,
                    "poll_answer_voters_array"
                    / Array(
                        this.poll_answer_voters_num, self.poll_answer_voters_struct()
                    ),
                ),
            ),
            "total_voters" / If(this.flags.total, Int32ul),
            "poll_recent_voters"
            / If(
                this.flags.recent_voters,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "poll_answer_voters_num" / Int32ul,
                    "poll_answer_voters_array"
                    / Array(this.poll_answer_voters_num, Int32ul),
                ),
            ),
        )

    def poll_results_struct(self):
        return Struct(
            "sname" / Computed("poll_results"),
            "signature" / Hex(Const(0xBADCC1A3, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul, min=1, voters=2, total=4, recent_voters=8, has_solution=16
            ),
            "poll_answer_voters"
            / If(
                this.flags.voters,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "poll_answer_voters_num" / Int32ul,
                    "poll_answer_voters_array"
                    / Array(
                        this.poll_answer_voters_num, self.poll_answer_voters_struct()
                    ),
                ),
            ),
            "total_voters" / If(this.flags.total, Int32ul),
            "poll_recent_voters"
            / If(
                this.flags.has_recent_voters,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "poll_answer_voters_num" / Int32ul,
                    "poll_answer_voters_array"
                    / Array(this.poll_answer_voters_num, Int32ul),
                ),
            ),
            "solution" / If(this.flags.has_solution, self.tstring_struct),
            "solution_entities"
            / If(
                this.flags.has_solution,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "entities_num" / Int32ul,
                    "entities_array"
                    / Array(
                        this.entities_num,
                        self.message_entity_structures("message_entity"),
                    ),
                ),
            ),
        )

    def poll_results_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xBADCC1A3: LazyBound(lambda: self.poll_results_struct()),
            0x5755785A: LazyBound(lambda: self.poll_results_layer108_struct()),
            0xC87024A2: LazyBound(lambda: self.poll_results_layer111_struct()),
        }
        return "poll_results_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def reaction_count_struct(self):
        return Struct(
            "sname" / Computed("reaction_count"),
            "signature" / Hex(Const(0x6FB250D1, Int32ul)),
            "flags" / FlagsEnum(Int32ul, chosen=1),
            "reaction" / self.tstring_struct,
            "count" / Int32ul,
        )

    # --------------------------------------------------------------------------

    def reply_keyboard_hide_struct(self):
        return Struct(
            "sname" / Computed("reply_keyboard_hide"),
            "signature" / Hex(Const(0xA03E5B85, Int32ul)),
            "flags" / FlagsEnum(Int32ul, selective=4),
        )

    def reply_keyboard_force_reply_struct(self):
        return Struct(
            "sname" / Computed("reply_keyboard_force_reply"),
            "signature" / Hex(Const(0xF4108AA0, Int32ul)),
            "flags" / FlagsEnum(Int32ul, single_use=2, selective=4),
        )

    def reply_keyboard_markup_struct(self):
        return Struct(
            "sname" / Computed("reply_keyboard_markup"),
            "signature" / Hex(Const(0x3502758C, Int32ul)),
            "flags" / FlagsEnum(Int32ul, resize=1, single_use=2, selective=4),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "keyboard_button_rows_num" / Int32ul,
            "keyboard_button_rows"
            / Array(this.keyboard_button_rows_num, self.keyboard_button_row_struct()),
        )

    def reply_inline_markup_struct(self):
        return Struct(
            "sname" / Computed("reply_inline_markup"),
            "signature" / Hex(Const(0x48A30254, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "keyboard_button_rows_num" / Int32ul,
            "keyboard_button_rows"
            / Array(this.keyboard_button_rows_num, self.keyboard_button_row_struct()),
        )

    def reply_markup_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xA03E5B85: LazyBound(lambda: self.reply_keyboard_hide_struct()),
            0xF4108AA0: LazyBound(lambda: self.reply_keyboard_force_reply_struct()),
            0x3502758C: LazyBound(lambda: self.reply_keyboard_markup_struct()),
            0x48A30254: LazyBound(lambda: self.reply_inline_markup_struct()),
        }
        return "reply_markup_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def restriction_reason_struct(self):
        return Struct(
            "sname" / Computed("restriction_reason"),
            "signature" / Hex(Const(0xD072ACB4, Int32ul)),
            "platform" / self.tstring_struct,
            "reason" / self.tstring_struct,
            "text" / self.tstring_struct,
        )

    # --------------------------------------------------------------------------

    def send_message_record_round_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_record_round_action"),
            "signature" / Hex(Const(0x88F27FBC, Int32ul)),
        )

    def send_message_upload_document_action_old_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_document_action_old"),
            "signature" / Hex(Const(0x8FAEE98E, Int32ul)),
        )

    def send_message_upload_video_action_old_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_video_action_old"),
            "signature" / Hex(Const(0x92042FF7, Int32ul)),
        )

    def send_message_upload_photo_action_old_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_photo_action_old"),
            "signature" / Hex(Const(0x990A3C1A, Int32ul)),
        )

    def send_message_record_video_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_record_video_action"),
            "signature" / Hex(Const(0xA187D66F, Int32ul)),
        )

    def send_message_upload_document_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_document_action"),
            "signature" / Hex(Const(0xAA0CD9E4, Int32ul)),
            "progress" / Int32ul,
        )

    def send_message_upload_photo_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_photo_action"),
            "signature" / Hex(Const(0xD1D34A26, Int32ul)),
            "progress" / Int32ul,
        )

    def send_message_record_audio_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_record_audio_action"),
            "signature" / Hex(Const(0xD52F73F7, Int32ul)),
        )

    def send_message_game_play_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_game_play_action"),
            "signature" / Hex(Const(0xDD6A8F48, Int32ul)),
        )

    def send_message_upload_audio_action_old_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_audio_action_old"),
            "signature" / Hex(Const(0xE6AC8A6F, Int32ul)),
        )

    def send_message_upload_video_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_video_action"),
            "signature" / Hex(Const(0xE9763AEC, Int32ul)),
            "progress" / Int32ul,
        )

    def send_message_upload_audio_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_audio_action"),
            "signature" / Hex(Const(0xF351D7AB, Int32ul)),
            "progress" / Int32ul,
        )

    def send_message_cancel_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_cancel_action"),
            "signature" / Hex(Const(0xFD5EC8F5, Int32ul)),
        )

    def send_message_typing_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_typing_action"),
            "signature" / Hex(Const(0x16BF744E, Int32ul)),
        )

    def send_message_geo_location_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_geo_location_action"),
            "signature" / Hex(Const(0x176F8BA1, Int32ul)),
        )

    def send_message_upload_round_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_upload_round_action"),
            "signature" / Hex(Const(0x243E1C66, Int32ul)),
            "progress" / Int32ul,
        )

    def send_message_choose_contact_action_struct(self):
        return Struct(
            "sname" / Computed("send_message_choose_contact_action"),
            "signature" / Hex(Const(0x628CBC6F, Int32ul)),
        )

    def send_message_action_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x88F27FBC: LazyBound(
                lambda: self.send_message_record_round_action_struct()
            ),
            0x8FAEE98E: LazyBound(
                lambda: self.send_message_upload_document_action_old_struct()
            ),
            0x92042FF7: LazyBound(
                lambda: self.send_message_upload_video_action_old_struct()
            ),
            0x990A3C1A: LazyBound(
                lambda: self.send_message_upload_photo_action_old_struct()
            ),
            0xA187D66F: LazyBound(
                lambda: self.send_message_record_video_action_struct()
            ),
            0xAA0CD9E4: LazyBound(
                lambda: self.send_message_upload_document_action_struct()
            ),
            0xD1D34A26: LazyBound(
                lambda: self.send_message_upload_photo_action_struct()
            ),
            0xD52F73F7: LazyBound(
                lambda: self.send_message_record_audio_action_struct()
            ),
            0xDD6A8F48: LazyBound(lambda: self.send_message_game_play_action_struct()),
            0xE6AC8A6F: LazyBound(
                lambda: self.send_message_upload_audio_action_old_struct()
            ),
            0xE9763AEC: LazyBound(
                lambda: self.send_message_upload_video_action_struct()
            ),
            0xF351D7AB: LazyBound(
                lambda: self.send_message_upload_audio_action_struct()
            ),
            0xFD5EC8F5: LazyBound(lambda: self.send_message_cancel_action_struct()),
            0x16BF744E: LazyBound(lambda: self.send_message_typing_action_struct()),
            0x176F8BA1: LazyBound(
                lambda: self.send_message_geo_location_action_struct()
            ),
            0x243E1C66: LazyBound(
                lambda: self.send_message_upload_round_action_struct()
            ),
            0x628CBC6F: LazyBound(
                lambda: self.send_message_choose_contact_action_struct()
            ),
        }
        return "send_message_action_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def secure_value_type_bank_statement_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_bank_statement"),
            "signature" / Hex(Const(0x89137C0D, Int32ul)),
        )

    def secure_value_type_rental_agreement_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_rental_agreement"),
            "signature" / Hex(Const(0x8B883488, Int32ul)),
        )

    def secure_value_type_email_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_email"),
            "signature" / Hex(Const(0x8E3CA7EE, Int32ul)),
        )

    def secure_value_type_internal_passport_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_internal_passport"),
            "signature" / Hex(Const(0x99A48F23, Int32ul)),
        )

    def secure_value_type_passport_registration_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_passport_registration"),
            "signature" / Hex(Const(0x99E3806A, Int32ul)),
        )

    def secure_value_type_personal_details_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_personal_details"),
            "signature" / Hex(Const(0x9D2A81E3, Int32ul)),
        )

    def secure_value_type_identity_card_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_identity_card"),
            "signature" / Hex(Const(0xA0D0744B, Int32ul)),
        )

    def secure_value_type_phone_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_phone"),
            "signature" / Hex(Const(0xB320AADB, Int32ul)),
        )

    def secure_value_type_address_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_address"),
            "signature" / Hex(Const(0xCBE31E26, Int32ul)),
        )

    def secure_value_type_temporary_registration_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_temporary_registration"),
            "signature" / Hex(Const(0xEA02EC33, Int32ul)),
        )

    def secure_value_type_utility_bill_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_utility_bill"),
            "signature" / Hex(Const(0xFC36954E, Int32ul)),
        )

    def secure_value_type_driver_license_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_driver_license"),
            "signature" / Hex(Const(0x06E425C4, Int32ul)),
        )

    def secure_value_type_passport_struct(self):
        return Struct(
            "sname" / Computed("secure_value_type_passport"),
            "signature" / Hex(Const(0x3DAC6A00, Int32ul)),
        )

    def secure_value_type_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xCBE31E26: LazyBound(lambda: self.secure_value_type_address_struct()),
            0x89137C0D: LazyBound(
                lambda: self.secure_value_type_bank_statement_struct()
            ),
            0x06E425C4: LazyBound(
                lambda: self.secure_value_type_driver_license_struct()
            ),
            0x8E3CA7EE: LazyBound(lambda: self.secure_value_type_email_struct()),
            0xA0D0744B: LazyBound(
                lambda: self.secure_value_type_identity_card_struct()
            ),
            0x99A48F23: LazyBound(
                lambda: self.secure_value_type_internal_passport_struct()
            ),
            0x3DAC6A00: LazyBound(lambda: self.secure_value_type_passport_struct()),
            0x99E3806A: LazyBound(
                lambda: self.secure_value_type_passport_registration_struct()
            ),
            0x9D2A81E3: LazyBound(
                lambda: self.secure_value_type_personal_details_struct()
            ),
            0xB320AADB: LazyBound(lambda: self.secure_value_type_phone_struct()),
            0x8B883488: LazyBound(
                lambda: self.secure_value_type_rental_agreement_struct()
            ),
            0xEA02EC33: LazyBound(
                lambda: self.secure_value_type_temporary_registration_struct()
            ),
            0xFC36954E: LazyBound(lambda: self.secure_value_type_utility_bill_struct()),
        }
        return "secure_value_type_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def text_strike_struct(self):
        return Struct(
            "sname" / Computed("text_strike"),
            "signature" / Hex(Const(0x9BF8BB95, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_underline_struct(self):
        return Struct(
            "sname" / Computed("text_underline"),
            "signature" / Hex(Const(0xC12622C4, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_superscript_struct(self):
        return Struct(
            "sname" / Computed("text_superscript"),
            "signature" / Hex(Const(0xC7FB5E01, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_italic_struct(self):
        return Struct(
            "sname" / Computed("text_italic"),
            "signature" / Hex(Const(0xD912A59C, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_empty_struct(self):
        return Struct(
            "sname" / Computed("text_empty"),
            "signature" / Hex(Const(0xDC3D824F, Int32ul)),
        )

    def text_email_struct(self):
        return Struct(
            "sname" / Computed("text_email"),
            "signature" / Hex(Const(0xDE5A0DD6, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "email" / self.tstring_struct,
        )

    def text_subscript_struct(self):
        return Struct(
            "sname" / Computed("text_subscript"),
            "signature" / Hex(Const(0xED6A8504, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_marked_struct(self):
        return Struct(
            "sname" / Computed("text_marked"),
            "signature" / Hex(Const(0x034B8621, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_image_struct(self):
        return Struct(
            "sname" / Computed("text_image"),
            "signature" / Hex(Const(0x081CCF4F, Int32ul)),
            "document_id" / Int64ul,
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def text_phone_struct(self):
        return Struct(
            "sname" / Computed("text_phone"),
            "signature" / Hex(Const(0x1CCB966A, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "phone" / self.tstring_struct,
        )

    def text_anchor_struct(self):
        return Struct(
            "sname" / Computed("text_anchor"),
            "signature" / Hex(Const(0x35553762, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "name" / self.tstring_struct,
        )

    def text_url_struct(self):
        return Struct(
            "sname" / Computed("text_url"),
            "signature" / Hex(Const(0x3C2884C1, Int32ul)),
            "text" / self.rich_text_structures("text"),
            "url" / self.tstring_struct,
            "webpage_id" / Int64ul,
        )

    def text_bold_struct(self):
        return Struct(
            "sname" / Computed("text_bold"),
            "signature" / Hex(Const(0x6724ABC4, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_fixed_struct(self):
        return Struct(
            "sname" / Computed("text_fixed"),
            "signature" / Hex(Const(0x6C3F19B9, Int32ul)),
            "text" / self.rich_text_structures("text"),
        )

    def text_concat_struct(self):
        return Struct(
            "sname" / Computed("text_concat"),
            "signature" / Hex(Const(0x7E6260D7, Int32ul)),
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "rich_texts_num" / Int32ul,
            "rich_texts"
            / Array(this.rich_texts_num, self.rich_text_structures("rich_text")),
        )

    def text_plain_struct(self):
        return Struct(
            "sname" / Computed("text_plain"),
            "signature" / Hex(Const(0x744694E0, Int32ul)),
            "text" / self.tstring_struct,
        )

    def rich_text_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x744694E0: LazyBound(lambda: self.text_plain_struct()),
            0xC12622C4: LazyBound(lambda: self.text_underline_struct()),
            0xC7FB5E01: LazyBound(lambda: self.text_superscript_struct()),
            0xD912A59C: LazyBound(lambda: self.text_italic_struct()),
            0xDC3D824F: LazyBound(lambda: self.text_empty_struct()),
            0xDE5A0DD6: LazyBound(lambda: self.text_email_struct()),
            0xED6A8504: LazyBound(lambda: self.text_subscript_struct()),
            0x034B8621: LazyBound(lambda: self.text_marked_struct()),
            0x081CCF4F: LazyBound(lambda: self.text_image_struct()),
            0x1CCB966A: LazyBound(lambda: self.text_phone_struct()),
            0x35553762: LazyBound(lambda: self.text_anchor_struct()),
            0x3C2884C1: LazyBound(lambda: self.text_url_struct()),
            0x6724ABC4: LazyBound(lambda: self.text_bold_struct()),
            0x6C3F19B9: LazyBound(lambda: self.text_fixed_struct()),
            0x7E6260D7: LazyBound(lambda: self.text_concat_struct()),
            0x9BF8BB95: LazyBound(lambda: self.text_strike_struct()),
        }
        return "rich_text_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def theme_settings_struct(self):
        return Struct(
            "sname" / Computed("theme_settings"),
            "signature" / Hex(Const(0x9C14984A, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_top_color=1, has_wallpaper=2),
            "base_theme" / self.base_theme_structures("base_theme"),
            "accent_color" / Int32ul,
            "message_top_color" / If(this.flags.has_top_color, Int32ul),
            "message_bottom_color" / If(this.flags.has_top_color, Int32ul),
            "wallpaper"
            / If(this.flags.has_wallpaper, self.wall_paper_structures("wallpaper")),
        )

    # --------------------------------------------------------------------------

    def user_full_layer98_struct(self):
        return Struct(
            "sname" / Computed("user_full_layer98"),
            "signature" / Hex(Const(0x8EA4A881, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                is_blocked=1,
                has_about=2,
                has_profile_photo=4,
                has_bot_info=8,
                phone_calls_available=16,
                phone_calls_private=32,
                has_pinned_msg_id=64,
                can_pin_message=128,
            ),
            "user" / self.user_structures("user"),
            "about" / If(this.flags.has_about, self.tstring_struct),
            "link" / self.contacts_link_layer101_struct(),
            "profile_photo"
            / If(this.flags.has_profile_photo, self.photo_structures("profile_photo")),
            "notify_settings" / self.peer_notify_settings_structures("notify_settings"),
            "bot_info"
            / If(this.flags.has_bot_info, self.bot_info_structures("bot_info")),
            "pinned_msg_id" / If(this.flags.has_pinned_msg_id, Int32ul),
            "common_chats_count" / Int32ul,
        )

    def user_full_layer101_struct(self):
        return Struct(
            "sname" / Computed("user_full_layer101"),
            "signature" / Hex(Const(0x745559CC, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                is_blocked=1,
                has_about=2,
                has_profile_photo=4,
                has_bot_info=8,
                phone_calls_available=16,
                phone_calls_private=32,
                has_pinned_msg_id=64,
                can_pin_message=128,
                has_folder_id=2048,
            ),
            "user" / self.user_structures("user"),
            "about" / If(this.flags.has_about, self.tstring_struct),
            "link" / self.contacts_link_layer101_struct(),
            "profile_photo"
            / If(this.flags.has_profile_photo, self.photo_structures("profile_photo")),
            "notify_settings" / self.peer_notify_settings_structures("notify_settings"),
            "bot_info"
            / If(this.flags.has_bot_info, self.bot_info_structures("bot_info")),
            "pinned_msg_id" / If(this.flags.has_pinned_msg_id, Int32ul),
            "common_chats_count" / Int32ul,
            "folder_id" / If(this.flags.has_folder_id, Int32ul),
        )

    def user_full_struct(self):
        return Struct(
            "sname" / Computed("user_full"),
            "signature" / Hex(Const(0xEDF17C12, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                is_blocked=1,
                has_about=2,
                has_profile_photo=4,
                has_bot_info=8,
                phone_calls_available=16,
                phone_calls_private=32,
                has_pinned_msg_id=64,
                can_pin_message=128,
                has_folder_id=2048,
                has_scheduled=4096,
            ),
            "user" / self.user_structures("user"),
            "about" / If(this.flags.has_about, self.tstring_struct),
            "settings" / self.peer_settings_structures("peer_settings"),
            "profile_photo"
            / If(this.flags.has_profile_photo, self.photo_structures("profile_photo")),
            "notify_settings" / self.peer_notify_settings_structures("notify_settings"),
            "bot_info"
            / If(this.flags.has_bot_info, self.bot_info_structures("bot_info")),
            "pinned_msg_id" / If(this.flags.has_pinned_msg_id, Int32ul),
            "common_chats_count" / Int32ul,
            "folder_id" / If(this.flags.has_folder_id, Int32ul),
        )

    def user_full_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x745559CC: LazyBound(lambda: self.user_full_layer101_struct()),
            0x8EA4A881: LazyBound(lambda: self.user_full_layer98_struct()),
            0xEDF17C12: LazyBound(lambda: self.user_full_struct()),
        }
        return "user_full_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def user_layer104_struct(self):
        return Struct(
            "sname" / Computed("user_layer104"),
            "signature" / Hex(Const(0x2E13F4C3, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_access_hash=1,
                has_first_name=2,
                has_last_name=4,
                has_username=8,
                has_phone=16,
                has_profile_photo=32,
                has_status=64,
                is_self=1024,
                is_contact=2048,
                is_mutual_contact=4096,
                is_deleted=8192,
                is_bot=16384,
                is_bot_chat_history=32768,
                is_bot_no_chats=65536,
                is_verified=131072,
                is_restricted=262144,
                has_lang_code=4194304,
                has_bot_inline_placeholder=524288,
                has_min=1048576,
                is_bot_inline_geo=2097152,
                is_support=8388608,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "first_name" / If(this.flags.has_first_name, self.tstring_struct),
            "last_name" / If(this.flags.has_last_name, self.tstring_struct),
            "username" / If(this.flags.has_username, self.tstring_struct),
            "phone" / If(this.flags.has_phone, self.tstring_struct),
            "photo"
            / If(
                this.flags.has_profile_photo,
                self.user_profile_photo_structures("photo"),
            ),
            "status" / If(this.flags.has_status, self.user_status_structures("status")),
            "bot_info_version" / If(this.flags.is_bot, Int32ul),
            "restriction_reason" / If(this.flags.is_restricted, self.tstring_struct),
            "bot_inline_placeholder"
            / If(this.flags.has_bot_inline_placeholder, self.tstring_struct),
            "lang_code" / If(this.flags.has_lang_code, self.tstring_struct),
        )

    def user_deleted_old_struct(self):
        return Struct(
            "sname" / Computed("user_deleted_old"),
            "signature" / Hex(Const(0xB29AD7CC, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
        )

    def user_deleted_old2_struct(self):
        return Struct(
            "sname" / Computed("user_deleted_old2"),
            "signature" / Hex(Const(0xD6016D7A, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "username" / self.tstring_struct,
        )

    def user_contact_old2_struct(self):
        return Struct(
            "sname" / Computed("user_contact_old2"),
            "signature" / Hex(Const(0xCAB35E18, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "username" / self.tstring_struct,
            "access_hash" / Int64ul,
            "phone" / self.tstring_struct,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
        )

    def user_layer65_struct(self):
        return Struct(
            "sname" / Computed("user_layer65"),
            "signature" / Hex(Const(0xD10D979A, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_access_hash=1,
                has_first_name=2,
                has_last_name=4,
                has_username=8,
                has_phone=16,
                has_profile_photo=32,
                has_status=64,
                is_self=1024,
                is_contact=2048,
                is_mutual_contact=4096,
                is_deleted=8192,
                is_bot=16384,
                is_bot_chat_history=32768,
                is_bot_no_chats=65536,
                is_verified=131072,
                is_restricted=262144,
                has_bot_inline_placeholder=524288,
                has_min=1048576,
                is_bot_inline_geo=2097152,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "first_name" / If(this.flags.has_first_name, self.tstring_struct),
            "last_name" / If(this.flags.has_last_name, self.tstring_struct),
            "username" / If(this.flags.has_username, self.tstring_struct),
            "phone" / If(this.flags.has_phone, self.tstring_struct),
            "photo"
            / If(
                this.flags.has_profile_photo,
                self.user_profile_photo_structures("photo"),
            ),
            "status" / If(this.flags.has_status, self.user_status_structures("status")),
            "bot_info_version" / If(this.flags.is_bot, Int32ul),
            "restriction_reason" / If(this.flags.is_restricted, self.tstring_struct),
            "bot_inline_placeholder"
            / If(this.flags.has_bot_inline_placeholder, self.tstring_struct),
        )

    def user_request_old2_struct(self):
        return Struct(
            "sname" / Computed("user_request_old2"),
            "signature" / Hex(Const(0xD9CCC4EF, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "username" / self.tstring_struct,
            "access_hash" / Int64ul,
            "phone" / self.tstring_struct,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
        )

    def user_contact_old_struct(self):
        return Struct(
            "sname" / Computed("user_contact_old"),
            "signature" / Hex(Const(0xF2FB8319, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "access_hash" / Int64ul,
            "phone" / self.tstring_struct,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
        )

    def user_foreign_old2_struct(self):
        return Struct(
            "sname" / Computed("user_foreign_old2"),
            "signature" / Hex(Const(0x075CF7A8, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "username" / self.tstring_struct,
            "access_hash" / Int64ul,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
        )

    def user_self_old3_struct(self):
        return Struct(
            "sname" / Computed("user_self_old3"),
            "signature" / Hex(Const(0x1C60E608, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "username" / self.tstring_struct,
            "phone" / self.tstring_struct,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
        )

    def user_empty_struct(self):
        return Struct(
            "sname" / Computed("user_empty"),
            "signature" / Hex(Const(0x200250BA, Int32ul)),
            "id" / Int32ul,
        )

    def user_old_struct(self):
        return Struct(
            "sname" / Computed("user_old"),
            "signature" / Hex(Const(0x22E49072, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_access_hash=1,
                has_first_name=2,
                has_last_name=4,
                has_username=8,
                has_phone=16,
                has_profile_photo=32,
                has_status=64,
                is_self=1024,
                is_contact=2048,
                is_mutual_contact=4096,
                is_deleted=8192,
                is_bot=16384,
                is_bot_chat_history=32768,
                is_bot_no_chats=65536,
                is_verified=131072,
                is_explicit_content=262144,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "first_name" / If(this.flags.has_first_name, self.tstring_struct),
            "last_name" / If(this.flags.has_last_name, self.tstring_struct),
            "username" / If(this.flags.has_username, self.tstring_struct),
            "phone" / If(this.flags.has_phone, self.tstring_struct),
            "photo"
            / If(
                this.flags.has_profile_photo,
                self.user_profile_photo_structures("photo"),
            ),
            "status" / If(this.flags.has_status, self.user_status_structures("status")),
            "bot_info_version" / If(this.flags.is_bot, Int32ul),
        )

    def user_request_old_struct(self):
        return Struct(
            "sname" / Computed("user_request_old"),
            "signature" / Hex(Const(0x22E8CEB0, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "access_hash" / Int64ul,
            "phone" / self.tstring_struct,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
        )

    def user_foreign_old_struct(self):
        return Struct(
            "sname" / Computed("user_foreign_old"),
            "signature" / Hex(Const(0x5214C89D, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "access_hash" / Int64ul,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
        )

    def user_self_old2_struct(self):
        return Struct(
            "sname" / Computed("user_self_old2"),
            "signature" / Hex(Const(0x7007B451, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "username" / self.tstring_struct,
            "phone" / self.tstring_struct,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
            "inactive" / self.tbool_struct,
        )

    def user_self_old_struct(self):
        return Struct(
            "sname" / Computed("user_self_old"),
            "signature" / Hex(Const(0x720535EC, Int32ul)),
            "id" / Int32ul,
            "first_name" / self.tstring_struct,
            "last_name" / self.tstring_struct,
            "phone" / self.tstring_struct,
            "photo" / self.user_profile_photo_structures("photo"),
            "status" / self.user_status_structures("status"),
            "inactive" / self.tbool_struct,
        )

    def user_struct(self):
        return Struct(
            "sname" / Computed("user_struct"),
            "signature" / Hex(Const(0x938458C1, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_access_hash=1,
                has_first_name=2,
                has_last_name=4,
                has_username=8,
                has_phone=16,
                has_profile_photo=32,
                has_status=64,
                is_self=1024,
                is_contact=2048,
                is_mutual_contact=4096,
                is_deleted=8192,
                is_bot=16384,
                is_bot_chat_history=32768,
                is_bot_no_chats=65536,
                is_min=1048576,
                is_verified=131072,
                is_bot_inline_geo=2097152,
                is_restricted=262144,
                is_support=8388608,
            ),
            "id" / Int32ul,
            "access_hash" / If(this.flags.has_access_hash, Int64ul),
            "first_name" / If(this.flags.has_first_name, self.tstring_struct),
            "last_name" / If(this.flags.has_last_name, self.tstring_struct),
            "username" / If(this.flags.has_username, self.tstring_struct),
            "phone" / If(this.flags.has_phone, self.tstring_struct),
            "photo"
            / If(
                this.flags.has_profile_photo,
                self.user_profile_photo_structures("photo"),
            ),
            "status" / If(this.flags.has_status, self.user_status_structures("status")),
            "bot_info_version" / If(this.flags.is_bot, Int32ul),
            "restrictions"
            / If(
                this.flags.is_restricted,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "restrictions_num" / Int32ul,
                    "restrictions_array"
                    / Array(this.restrictions_num, self.restriction_reason_struct()),
                ),
            ),
        )

    def user_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x938458C1: LazyBound(lambda: self.user_struct()),
            0x2E13F4C3: LazyBound(lambda: self.user_layer104_struct()),
            0xB29AD7CC: LazyBound(lambda: self.user_deleted_old_struct()),
            0xCAB35E18: LazyBound(lambda: self.user_contact_old2_struct()),
            0xD10D979A: LazyBound(lambda: self.user_layer65_struct()),
            0xD6016D7A: LazyBound(lambda: self.user_deleted_old2_struct()),
            0xD9CCC4EF: LazyBound(lambda: self.user_request_old2_struct()),
            0xF2FB8319: LazyBound(lambda: self.user_contact_old_struct()),
            0x075CF7A8: LazyBound(lambda: self.user_foreign_old2_struct()),
            0x1C60E608: LazyBound(lambda: self.user_self_old3_struct()),
            0x200250BA: LazyBound(lambda: self.user_empty_struct()),
            0x22E49072: LazyBound(lambda: self.user_old_struct()),
            0x22E8CEB0: LazyBound(lambda: self.user_request_old_struct()),
            0x5214C89D: LazyBound(lambda: self.user_foreign_old_struct()),
            0x7007B451: LazyBound(lambda: self.user_self_old2_struct()),
            0x720535EC: LazyBound(lambda: self.user_self_old_struct()),
        }
        return "user_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def user_profile_photo_empty_struct(self):
        return Struct(
            "sname" / Computed("user_profile_photo_empty"),
            "signature" / Hex(Const(0x4F11BAE1, Int32ul)),
        )

    def user_profile_photo_layer97_struct(self):
        return Struct(
            "sname" / Computed("user_profile_photo_layer97"),
            "signature" / Hex(Const(0xD559D8C8, Int32ul)),
            "photo_id" / Int64ul,
            "photo_small" / self.file_location_structures("photo_small"),
            "photo_big" / self.file_location_structures("photo_big"),
        )

    def user_profile_photo_old_struct(self):
        return Struct(
            "sname" / Computed("user_profile_photo_old"),
            "signature" / Hex(Const(0x990D1493, Int32ul)),
            "photo_small" / self.file_location_structures("photo_small"),
            "photo_big" / self.file_location_structures("photo_big"),
        )

    def user_profile_photo_layer115_struct(self):
        return Struct(
            "sname" / Computed("user_profile_photo_layer115"),
            "signature" / Hex(Const(0xECD75D8C, Int32ul)),
            "photo_id" / Int64ul,
            "photo_small" / self.file_location_structures("photo_small"),
            "photo_big" / self.file_location_structures("photo_big"),
            "dc_id" / Int32ul,
        )

    def user_profile_photo_struct(self):
        return Struct(
            "sname" / Computed("user_profile_photo"),
            "signature" / Hex(Const(0x69D3AB26, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_video=1),
            "photo_id" / Int64ul,
            "photo_small" / self.file_location_structures("photo_small"),
            "photo_big" / self.file_location_structures("photo_big"),
            "dc_id" / Int32ul,
        )

    def user_profile_photo_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0x69D3AB26: LazyBound(lambda: self.user_profile_photo_struct()),
            0xECD75D8C: LazyBound(lambda: self.user_profile_photo_layer115_struct()),
            0xD559D8C8: LazyBound(lambda: self.user_profile_photo_layer97_struct()),
            0x4F11BAE1: LazyBound(lambda: self.user_profile_photo_empty_struct()),
            0x990D1493: LazyBound(lambda: self.user_profile_photo_old_struct()),
        }
        return "user_profile_photo_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def user_status_recently_struct(self):
        return Struct(
            "sname" / Computed("user_status_recently"),
            "signature" / Hex(Const(0xE26F42F1, Int32ul)),
        )

    def user_status_online_struct(self):
        return Struct(
            "sname" / Computed("user_status_online"),
            "signature" / Hex(Const(0xEDB93949, Int32ul)),
            "expires" / Int32ul,
        )

    def user_status_offline_struct(self):
        return Struct(
            "sname" / Computed("user_status_offline"),
            "signature" / Hex(Const(0x008C703F, Int32ul)),
            "expires" / Int32ul,
        )

    def user_status_last_week_struct(self):
        return Struct(
            "sname" / Computed("user_status_last_week"),
            "signature" / Hex(Const(0x07BF09FC, Int32ul)),
        )

    def user_status_last_month_struct(self):
        return Struct(
            "sname" / Computed("user_status_last_month"),
            "signature" / Hex(Const(0x77EBC742, Int32ul)),
        )

    def user_status_empty_struct(self):
        return Struct(
            "sname" / Computed("user_status_empty"),
            "signature" / Hex(Const(0x09D05049, Int32ul)),
        )

    def user_status_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xE26F42F1: LazyBound(lambda: self.user_status_recently_struct()),
            0xEDB93949: LazyBound(lambda: self.user_status_online_struct()),
            0x008C703F: LazyBound(lambda: self.user_status_offline_struct()),
            0x07BF09FC: LazyBound(lambda: self.user_status_last_week_struct()),
            0x09D05049: LazyBound(lambda: self.user_status_empty_struct()),
            0x77EBC742: LazyBound(lambda: self.user_status_last_month_struct()),
        }
        return "user_status_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def video_empty_layer45_struct(self):
        return Struct(
            "sname" / Computed("video_empty_layer45"),
            "signature" / Hex(Const(0xC10658A8, Int32ul)),
            "id" / Int64ul,
        )

    def video_old3_struct(self):
        return Struct(
            "sname" / Computed("video_old3"),
            "signature" / Hex(Const(0xEE9F4A4D, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "duration" / Int32ul,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def video_layer45_struct(self):
        return Struct(
            "sname" / Computed("video_layer45"),
            "signature" / Hex(Const(0xF72887D3, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "date" / self.ttimestamp_struct,
            "duration" / Int32ul,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def video_old2_struct(self):
        return Struct(
            "sname" / Computed("video_old2"),
            "signature" / Hex(Const(0x388FA391, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "caption" / self.tstring_struct,
            "duration" / Int32ul,
            "mime_type" / self.tstring_struct,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def video_encrypted_struct(self):
        return Struct(
            "sname" / Computed("video_encrypted"),
            "signature" / Hex(Const(0x55555553, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "caption" / self.tstring_struct,
            "duration" / Int32ul,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
            "key" / self.tbytes_struct,
            "iv" / self.tbytes_struct,
        )

    def video_old_struct(self):
        return Struct(
            "sname" / Computed("video_old"),
            "signature" / Hex(Const(0x5A04A49F, Int32ul)),
            "id" / Int64ul,
            "access_hash" / Int64ul,
            "user_id" / Int32ul,
            "date" / self.ttimestamp_struct,
            "caption" / self.tstring_struct,
            "duration" / Int32ul,
            "size" / Int32ul,
            "thumb" / self.photo_size_structures("thumb"),
            "dc_id" / Int32ul,
            "w" / Int32ul,
            "h" / Int32ul,
        )

    def video_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xC10658A8: LazyBound(lambda: self.video_empty_layer45_struct()),
            0xEE9F4A4D: LazyBound(lambda: self.video_old3_struct()),
            0xF72887D3: LazyBound(lambda: self.video_layer45_struct()),
            0x388FA391: LazyBound(lambda: self.video_old2_struct()),
            0x55555553: LazyBound(lambda: self.video_encrypted_struct()),
            0x5A04A49F: LazyBound(lambda: self.video_old_struct()),
        }
        return "video_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def video_size_struct(self):
        return Struct(
            "sname" / Computed("video_size"),
            "signature" / Hex(Const(0xE831C556, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_video_start_ts=1),
            "type" / self.tstring_struct,
            "location" / self.file_location_structures("location"),
            "w" / Int32ul,
            "h" / Int32ul,
            "size" / Int32ul,
            "video_start_ts" / If(this.flags.has_video_start_ts, Double),
        )

    def video_size_layer115_struct(self):
        return Struct(
            "sname" / Computed("video_size_layer115"),
            "signature" / Hex(Const(0x435BB987, Int32ul)),
            "type" / self.tstring_struct,
            "location" / self.file_location_structures("location"),
            "w" / Int32ul,
            "h" / Int32ul,
            "size" / Int32ul,
        )

    def video_size_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xE831C556: LazyBound(lambda: self.video_size_struct()),
            0x435BB987: LazyBound(lambda: self.video_size_layer115_struct()),
        }
        return "video_size_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def wall_paper_settings_layer106_struct(self):
        return Struct(
            "sname" / Computed("wall_paper_settings_layer106"),
            "signature" / Hex(Const(0xA12F40B8, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul, has_background_color=1, is_blur=2, is_motion=4, has_intensity=8
            ),
            "background_color" / If(this.flags.has_background_color, Int32ul),
            "intensity" / If(this.flags.has_intensity, Int32ul),
        )

    def wall_paper_settings_struct(self):
        return Struct(
            "sname" / Computed("wall_paper_settings"),
            "signature" / Hex(Const(0x05086CF8, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_background_color=1,
                is_blur=2,
                is_motion=4,
                has_intensity=8,
                has_second_background_color=16,
            ),
            "background_color" / If(this.flags.has_background_color, Int32ul),
            "second_background_color"
            / If(this.flags.has_second_background_color, Int32ul),
            "intensity" / If(this.flags.has_intensity, Int32ul),
            "rotation" / If(this.flags.has_second_background_color, Int32ul),
        )

    def wall_paper_settings_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xA12F40B8: LazyBound(lambda: self.wall_paper_settings_layer106_struct()),
            0x05086CF8: LazyBound(lambda: self.wall_paper_settings_struct()),
        }
        return "wall_paper_settings_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def wall_paper_no_file_struct(self):
        return Struct(
            "sname" / Computed("wall_paper_no_file"),
            "signature" / Hex(Const(0x8AF40B25, Int32ul)),
            "flags"
            / FlagsEnum(Int32ul, is_default=2, has_wallpaper_settings=4, is_dark=16),
            "wallpaper_settings"
            / If(
                this.flags.has_wallpaper_settings,
                self.wall_paper_settings_structures("wall_paper_settings"),
            ),
        )

    def wall_paper_layer94_struct(self):
        return Struct(
            "sname" / Computed("wall_paper_layer94"),
            "signature" / Hex(Const(0xF04F91EC, Int32ul)),
            "id" / Int64ul,
            "flags" / FlagsEnum(Int32ul, is_creator=1, is_default=2),
            "access_hash" / Int64ul,
            "slug" / self.tstring_struct,
            "document" / self.document_structures("document"),
        )

    def wall_paper_struct(self):
        return Struct(
            "sname" / Computed("wall_paper"),
            "signature" / Hex(Const(0xA437C3ED, Int32ul)),
            "id" / Int64ul,
            "flags"
            / FlagsEnum(
                Int32ul, creator=1, default=2, wallpaper_settings=4, pattern=8, dark=16
            ),
            "access_hash" / Int64ul,
            "slug" / self.tstring_struct,
            "document" / self.document_structures("document"),
            "wallpaper_settings"
            / If(
                this.flags.wallpaper_settings,
                self.wall_paper_settings_structures("wall_paper_settings"),
            ),
        )

    def wall_paper_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xA437C3ED: LazyBound(lambda: self.wall_paper_struct()),
            0x8AF40B25: LazyBound(lambda: self.wall_paper_no_file_struct()),
            0xF04F91EC: LazyBound(lambda: self.wall_paper_layer94_struct()),
        }
        return "wall_paper_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def web_document_layer81_struct(self):
        return Struct(
            "sname" / Computed("web_document_layer81"),
            "signature" / Hex(Const(0xC61ACBD8, Int32ul)),
            "url" / self.tstring_struct,
            "access_hash" / Int64ul,
            "size" / Int32ul,
            "mime_type" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document_attribute"),
            ),
        )

    def web_document_no_proxy_struct(self):
        return Struct(
            "sname" / Computed("web_document_no_proxy"),
            "signature" / Hex(Const(0xF9C8BCC6, Int32ul)),
            "url" / self.tstring_struct,
            "size" / Int32ul,
            "mime_type" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document_attribute"),
            ),
        )

    def web_document_struct(self):
        return Struct(
            "sname" / Computed("web_document"),
            "signature" / Hex(Const(0x1C570ED1, Int32ul)),
            "url" / self.tstring_struct,
            "access_hash" / Int64ul,
            "size" / Int32ul,
            "mime_type" / self.tstring_struct,
            "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
            "document_attributes_num" / Int32ul,
            "document_attributes"
            / Array(
                this.document_attributes_num,
                self.document_attribute_structures("document_attribute"),
            ),
        )

    def web_document_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xC61ACBD8: LazyBound(lambda: self.web_document_layer81_struct()),
            0xF9C8BCC6: LazyBound(lambda: self.web_document_no_proxy_struct()),
            0x1C570ED1: LazyBound(lambda: self.web_document_struct()),
        }
        return "web_document_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------

    def web_page_attribute_theme_struct(self):
        return Struct(
            "sname" / Computed("web_page_attribute_theme"),
            "signature" / Hex(Const(0x54B56617, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_documents=1, has_theme_settings=2),
            "documents"
            / If(
                this.flags.has_documents,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "documents_num" / Int32ul,
                    "documents_array"
                    / Array(this.documents_num, self.document_structures("document")),
                ),
            ),
            "theme_settings"
            / If(this.flags.has_theme_settings, self.theme_settings_struct()),
        )

    # --------------------------------------------------------------------------

    def web_page_not_modified_struct(self):
        return Struct(
            "sname" / Computed("web_page_not_modified"),
            "signature" / Hex(Const(0x7311CA11, Int32ul)),
            "flags" / FlagsEnum(Int32ul, has_cached_page_views=1),
            "cached_page_views" / If(this.flags.has_cached_page_views, Int32ul),
        )

    def web_page_not_modified_layer110_struct(self):
        return Struct(
            "sname" / Computed("web_page_not_modified_layer110"),
            "signature" / Hex(Const(0x85849473, Int32ul)),
        )

    def web_page_old_struct(self):
        return Struct(
            "sname" / Computed("web_page_old"),
            "signature" / Hex(Const(0xA31EA0B5, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_type=1,
                has_site_name=2,
                has_title=4,
                has_description=8,
                has_photo=16,
                has_embed_url=32,
                has_embed_media=64,
                has_duration=128,
                has_author=256,
            ),
            "id" / Int64ul,
            "url" / self.tstring_struct,
            "display_url" / self.tstring_struct,
            "type" / If(this.flags.has_type, self.tstring_struct),
            "site_name" / If(this.flags.has_site_name, self.tstring_struct),
            "title" / If(this.flags.has_title, self.tstring_struct),
            "description" / If(this.flags.has_description, self.tstring_struct),
            "photo" / If(this.flags.has_photo, self.photo_structures("photo")),
            "embed_url" / If(this.flags.has_embed_url, self.tstring_struct),
            "embed_type" / If(this.flags.has_embed_url, self.tstring_struct),
            "embed_width" / If(this.flags.has_embed_media, Int32ul),
            "embed_height" / If(this.flags.has_embed_media, Int32ul),
            "duration" / If(this.flags.has_duration, Int32ul),
            "author" / If(this.flags.has_author, self.tstring_struct),
        )

    def web_page_pending_struct(self):
        return Struct(
            "sname" / Computed("web_page_pending"),
            "signature" / Hex(Const(0xC586DA1C, Int32ul)),
            "id" / Int64ul,
            "date" / Int32ul,
        )

    def web_page_layer58_struct(self):
        return Struct(
            "sname" / Computed("web_page_layer58"),
            "signature" / Hex(Const(0xCA820ED7, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_type=1,
                has_site_name=2,
                has_title=4,
                has_description=8,
                has_photo=16,
                has_embed_url=32,
                has_embed_media=64,
                has_duration=128,
                has_author=256,
                has_document=512,
            ),
            "id" / Int64ul,
            "url" / self.tstring_struct,
            "display_url" / self.tstring_struct,
            "type" / If(this.flags.has_type, self.tstring_struct),
            "site_name" / If(this.flags.has_site_name, self.tstring_struct),
            "title" / If(this.flags.has_title, self.tstring_struct),
            "description" / If(this.flags.has_description, self.tstring_struct),
            "photo" / If(this.flags.has_photo, self.photo_structures("photo")),
            "embed_url" / If(this.flags.has_embed_url, self.tstring_struct),
            "embed_type" / If(this.flags.has_embed_url, self.tstring_struct),
            "embed_width" / If(this.flags.has_embed_media, Int32ul),
            "embed_height" / If(this.flags.has_embed_media, Int32ul),
            "duration" / If(this.flags.has_duration, Int32ul),
            "author" / If(this.flags.has_author, self.tstring_struct),
            "document"
            / If(this.flags.has_document, self.document_structures("document")),
        )

    def web_page_url_pending_struct(self):
        return Struct(
            "sname" / Computed("web_page_url_pending"),
            "signature" / Hex(Const(0xD41A5167, Int32ul)),
            "url" / self.tstring_struct,
        )

    def web_page_empty_struct(self):
        return Struct(
            "sname" / Computed("web_page_empty"),
            "signature" / Hex(Const(0xEB1477E8, Int32ul)),
            "id" / Int64ul,
        )

    def web_page_layer104_struct(self):
        return Struct(
            "sname" / Computed("web_page_layer104"),
            "signature" / Hex(Const(0x5F07B4BC, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                has_type=1,
                has_site_name=2,
                has_title=4,
                has_description=8,
                has_photo=16,
                has_embed_url=32,
                has_embed_media=64,
                has_duration=128,
                has_author=256,
                has_document=512,
                is_cached=1024,
            ),
            "id" / Int64ul,
            "url" / self.tstring_struct,
            "display_url" / self.tstring_struct,
            "hash" / Int32ul,
            "type" / If(this.flags.has_type, self.tstring_struct),
            "site_name" / If(this.flags.has_site_name, self.tstring_struct),
            "title" / If(this.flags.has_title, self.tstring_struct),
            "description" / If(this.flags.has_description, self.tstring_struct),
            "photo" / If(this.flags.has_photo, self.photo_structures("photo")),
            "embed_url" / If(this.flags.has_embed_url, self.tstring_struct),
            "embed_type" / If(this.flags.has_embed_url, self.tstring_struct),
            "embed_width" / If(this.flags.has_embed_media, Int32ul),
            "embed_height" / If(this.flags.has_embed_media, Int32ul),
            "duration" / If(this.flags.has_duration, Int32ul),
            "author" / If(this.flags.has_author, self.tstring_struct),
            "document"
            / If(this.flags.has_document, self.document_structures("document")),
            "cached_page"
            / If(this.flags.is_cached, self.page_structures("cached_page")),
        )

    def web_page_layer107_struct(self):
        return Struct(
            "sname" / Computed("web_page_layer107"),
            "signature" / Hex(Const(0xFA64E172, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                type=1,
                site_name=2,
                title=4,
                description=8,
                photo=16,
                embed_url=32,
                embed_media=64,
                duration=128,
                author=256,
                document=512,
                cached=1024,
                has_webpage_attr_theme=2048,
            ),
            "id" / Int64ul,
            "url" / self.tstring_struct,
            "display_url" / self.tstring_struct,
            "hash" / Int32ul,
            "type" / If(this.flags.type, self.tstring_struct),
            "site_name" / If(this.flags.site_name, self.tstring_struct),
            "title" / If(this.flags.title, self.tstring_struct),
            "description" / If(this.flags.description, self.tstring_struct),
            "photo" / If(this.flags.photo, self.photo_structures("photo")),
            "embed_url" / If(this.flags.embed_url, self.tstring_struct),
            "embed_type" / If(this.flags.embed_url, self.tstring_struct),
            "embed_width" / If(this.flags.embed_media, Int32ul),
            "embed_height" / If(this.flags.embed_media, Int32ul),
            "duration" / If(this.flags.duration, Int32ul),
            "author" / If(this.flags.author, self.tstring_struct),
            "document" / If(this.flags.document, self.document_structures("document")),
            "webpage_attribute_theme"
            / If(
                this.flags.has_webpage_attr_theme,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "documents_num" / Int32ul,
                    "documents_array"
                    / Array(this.documents_num, self.document_structures("document")),
                ),
            ),
            "cached_page" / If(this.flags.cached, self.page_structures("cached_page")),
        )

    def web_page_struct(self):
        return Struct(
            "sname" / Computed("web_page"),
            "signature" / Hex(Const(0xE89C45B2, Int32ul)),
            "flags"
            / FlagsEnum(
                Int32ul,
                type=1,
                site_name=2,
                title=4,
                description=8,
                photo=16,
                embed_url=32,
                embed_media=64,
                duration=128,
                author=256,
                document=512,
                cached=1024,
                webpage_attr_theme=4096,
            ),
            "id" / Int64ul,
            "url" / self.tstring_struct,
            "display_url" / self.tstring_struct,
            "hash" / Int32ul,
            "type" / If(this.flags.type, self.tstring_struct),
            "site_name" / If(this.flags.site_name, self.tstring_struct),
            "title" / If(this.flags.title, self.tstring_struct),
            "description" / If(this.flags.description, self.tstring_struct),
            "photo" / If(this.flags.photo, self.photo_structures("photo")),
            "embed_url" / If(this.flags.embed_url, self.tstring_struct),
            "embed_type" / If(this.flags.embed_url, self.tstring_struct),
            "embed_width" / If(this.flags.embed_media, Int32ul),
            "embed_height" / If(this.flags.embed_media, Int32ul),
            "duration" / If(this.flags.duration, Int32ul),
            "author" / If(this.flags.author, self.tstring_struct),
            "document" / If(this.flags.document, self.document_structures("document")),
            "cached_page" / If(this.flags.cached, self.page_structures("cached_page")),
            "webpage_attribute_theme"
            / If(
                this.flags.webpage_attr_theme,
                Struct(
                    "_vector_sig" / Hex(Const(0x1CB5C415, Int32ul)),
                    "webpage_attribute_num" / Int32ul,
                    "webpage_attribute_array"
                    / Array(
                        this.webpage_attribute_num,
                        self.web_page_attribute_theme_struct(),
                    ),
                ),
            ),
        )

    def web_page_structures(self, name):
        # pylint: disable=C0301
        tag_map = {
            0xE89C45B2: LazyBound(lambda: self.web_page_struct()),
            0x5F07B4BC: LazyBound(lambda: self.web_page_layer104_struct()),
            0xFA64E172: LazyBound(lambda: self.web_page_layer107_struct()),
            0xD41A5167: LazyBound(lambda: self.web_page_url_pending_struct()),
            0xCA820ED7: LazyBound(lambda: self.web_page_layer58_struct()),
            0xC586DA1C: LazyBound(lambda: self.web_page_pending_struct()),
            0xA31EA0B5: LazyBound(lambda: self.web_page_old_struct()),
            0x7311CA11: LazyBound(lambda: self.web_page_not_modified_struct()),
            0x85849473: LazyBound(lambda: self.web_page_not_modified_layer110_struct()),
            0xEB1477E8: LazyBound(lambda: self.web_page_empty_struct()),
        }
        return "web_page_structures" / Struct(
            "_signature" / Peek(Int32ul), name / Switch(this._signature, tag_map)
        )

    # --------------------------------------------------------------------------
    # Telegram TDSs definitions
    # Actual version created mixing versions: 0.1.137, 5.5.0, 5.6.2
    # --------------------------------------------------------------------------

    tdss_callbacks = {
        # pylint: disable=C0301
        0xB8D0AFDF: (None, "account_days_ttl", None),  # -1194283041
        0xE7027C94: (None, "account_accept_authorization", None),  # -419267436
        0xAD2E1CD8: (None, "account_authorization_form", None),  # -1389486888
        0x1250ABDE: (None, "account_authorizations", None),  # 307276766
        0x63CACF26: (None, "account_auto_download_settings", None),  # 1674235686
        0xC1CBD5B6: (None, "account_cancel_password_email", None),  # -1043606090
        0x70C32EDB: (None, "account_change_phone", None),  # 1891839707
        0x2714D86C: (None, "account_check_username", None),  # 655677548
        0x8FDF1920: (None, "account_confirm_password_email", None),  # -1881204448
        0x5F2178C3: (None, "account_confirm_phone", None),  # 1596029123
        0x8432C21F: (None, "account_create_theme", None),  # -2077048289
        0x418D4E0B: (None, "account_delete_account", None),  # 1099779595
        0xB880BC4B: (None, "account_delete_secure_value", None),  # -1199522741
        0x08FC711D: (None, "account_get_account_ttl", None),  # 150761757
        0xB288BC7D: (None, "account_get_all_secure_values", None),  # -1299661699
        0xB86BA8E1: (None, "account_get_authorization_form", None),  # -1200903967
        0xE320C158: (None, "account_get_authorizations", None),  # -484392616
        0x56DA0B3F: (None, "account_get_auto_download_settings", None),  # 1457130303
        0x9F07C728: (
            None,
            "account_get_contact_sign_up_notification",
            None,
        ),  # -1626880216
        0xEB2B4CF6: (None, "account_get_global_privacy_settings", None),  # -349483786
        0x65AD71DC: (None, "account_get_multi_wall_papers", None),  # 1705865692
        0x53577479: (None, "account_get_notify_exceptions", None),  # 1398240377
        0x12B3AD31: (None, "account_get_notify_settings", None),  # 313765169
        0x548A30F5: (None, "account_get_password", None),  # 1418342645
        0x9CD4EAF9: (None, "account_get_password_settings", None),  # -1663767815
        0xDADBC950: (None, "account_get_privacy", None),  # -623130288
        0x73665BC2: (None, "account_get_secure_value", None),  # 1936088002
        0x8D9D742B: (None, "account_get_theme", None),  # -1919060949
        0x285946F8: (None, "account_get_themes", None),  # 676939512
        0x449E0B51: (None, "account_get_tmp_password", None),  # 1151208273
        0xFC8DDBEA: (None, "account_get_wall_paper", None),  # -57811990
        0xAABB1763: (None, "account_get_wall_papers", None),  # -1430579357
        0xC04CFAC2: (None, "account_get_wall_papers_v_0_1_317"),  # -1068696894
        0x182E6D6F: (None, "account_get_web_authorizations", None),  # 405695855
        0x7AE43737: (None, "account_install_theme", None),  # 2061776695
        0xFEED5769: (None, "account_install_wall_paper", None),  # -18000023
        0xAD2641F8: (None, "account_password", None),  # -1390001672
        0xC23727C9: (None, "account_password_input_settings", None),  # -1036572727
        0x9A5C33E5: (None, "account_password_settings", None),  # -1705233435
        0x50A04E45: (None, "account_privacy_rules", None),  # 1352683077
        0x68976C6F: (None, "account_register_device", None),  # 1754754159
        0x554ABB6F: (None, "account_privacy_rules_v_5_6_2", None),  # 1430961007
        0x446C712C: (None, "account_register_device_v_0_1_317", None),  # 1147957548
        0x5CBEA590: (None, "account_register_device_v_5_6_2", None),  # 1555998096
        0xAE189D5F: (None, "account_report_peer", None),  # -1374118561
        0x7A7F2A15: (None, "account_resend_password_email", None),  # 2055154197
        0xDF77F3BC: (None, "account_reset_authorization", None),  # -545786948
        0xDB7E1747: (None, "account_reset_notify_settings", None),  # -612493497
        0xBB3B9804: (None, "account_reset_wall_papers", None),  # -1153722364
        0x2D01B9EF: (None, "account_reset_web_authorization", None),  # 755087855
        0x682D2594: (None, "account_reset_web_authorizations", None),  # 1747789204
        0x76F36233: (None, "account_save_auto_download_settings", None),  # 1995661875
        0x899FE31D: (None, "account_save_secure_value", None),  # -1986010339
        0xF257106C: (None, "account_save_theme", None),  # -229175188
        0x6C5A5B37: (None, "account_save_wall_paper", None),  # 1817860919
        0x82574AE5: (None, "account_send_change_phone_code", None),  # -2108208411
        0x1B3FAA88: (None, "account_send_confirm_phone_code", None),  # 457157256
        0x7011509F: (None, "account_send_verify_email_code", None),  # 1880182943
        0xA5A356F9: (None, "account_send_verify_phone_code", None),  # -1516022023
        0x811F854F: (None, "account_sent_email_code", None),  # -2128640689
        0x2442485E: (None, "account_set_account_ttl", None),  # 608323678
        0xCFF43F61: (
            None,
            "account_set_contact_sign_up_notification",
            None,
        ),  # -806076575
        0x1EDAAAC2: (None, "account_set_global_privacy_settings", None),  # 517647042
        0xC9F81CE8: (None, "account_set_privacy", None),  # -906486552
        0x7F676421: (None, "account_themes", None),  # 2137482273
        0xF41EB622: (None, "account_themes_not_modified", None),  # -199313886
        0xDB64FD34: (None, "account_tmp_password", None),  # -614138572
        0x3076C4BF: (None, "account_unregister_device", None),  # 813089983
        0x65C55B40: (None, "account_unregister_device_v_0_1_317"),  # 1707432768
        0x38DF3532: (None, "account_update_device_locked", None),  # 954152242
        0x84BE5B93: (None, "account_update_notify_settings", None),  # -2067899501
        0xA59B102F: (None, "account_update_password_settings", None),  # -1516564433
        0x78515775: (None, "account_update_profile", None),  # 2018596725
        0xF0888D68: (None, "account_update_profile_v_0_1_317"),  # -259486360
        0x6628562C: (None, "account_update_status", None),  # 1713919532
        0x5CB367D5: (None, "account_update_theme", None),  # 1555261397
        0x3E0BDD7C: (None, "account_update_username", None),  # 1040964988
        0x1C3DB333: (None, "account_upload_theme", None),  # 473805619
        0xDD853661: (None, "account_upload_wall_paper", None),  # -578472351
        0xECBA39DB: (None, "account_verify_email", None),  # -323339813
        0x4DD3A7F6: (None, "account_verify_phone", None),  # 1305716726
        0x702B65A9: (None, "account_wall_papers", None),  # 1881892265
        0x1C199183: (None, "account_wall_papers_not_modified", None),  # 471437699
        0xED56C9FC: (None, "account_web_authorizations", None),  # -313079300
        0x586988D8: (
            audio_empty_layer45_struct,
            "audio_empty_layer45",
            None,
        ),  # 1483311320
        0x555555F6: (audio_encrypted_struct, "audio_encrypted", None),  # 1431655926
        0xF9E35055: (audio_layer45_struct, "audio_layer45", None),  # -102543275
        0x427425E7: (audio_old_struct, "audio_old", None),  # 1114908135
        0xC7AC6496: (audio_old2_struct, "audio_old2", None),  # -945003370
        0xE894AD4D: (None, "auth_accept_login_token", None),  # -392909491
        0xCD050916: (None, "auth_authorization", None),  # -855308010
        0x44747E9A: (None, "auth_authorization_sign_up_required", None),  # 1148485274
        0xF6B673A4: (None, "auth_authorization_v_0_1_317"),  # -155815004
        0x1F040578: (None, "auth_cancel_code", None),  # 520357240
        0xD18B4D16: (None, "auth_check_password", None),  # -779399914
        0x6FE51DFB: (None, "auth_check_phone_v_5_6_2", None),  # 1877286395
        0x811EA28E: (None, "auth_checked_phone_v_5_6_2", None),  # -2128698738
        0xE300CC3B: (None, "auth_checked_phone_v_0_1_317"),  # -486486981
        0x741CD3E3: (None, "auth_code_type_call", None),  # 1948046307
        0x226CCEFB: (None, "auth_code_type_flash_call", None),  # 577556219
        0x72A3158C: (None, "auth_code_type_sms", None),  # 1923290508
        0xE5BFFFCD: (None, "auth_export_authorization", None),  # -440401971
        0xDF969C2D: (None, "auth_exported_authorization", None),  # -543777747
        0xB1B41517: (None, "auth_export_login_token", None),  # -1313598185
        0xE3EF9613: (None, "auth_import_authorization", None),  # -470837741
        0x95AC5CE4: (None, "auth_import_login_token", None),  # -1783866140
        0x5717DA40: (None, "auth_log_out", None),  # 1461180992
        0x629F1980: (None, "auth_login_token", None),  # 1654593920
        0x068E9916: (None, "auth_login_token_migrate_to", None),  # 110008598
        0x390D5C5E: (None, "auth_login_token_success", None),  # 957176926
        0x137948A5: (None, "auth_password_recovery", None),  # 326715557
        0x4EA56E92: (None, "auth_recover_password", None),  # 1319464594
        0xD897BC66: (None, "auth_request_password_recovery", None),  # -661144474
        0x3EF1A9BF: (None, "auth_resend_code", None),  # 1056025023
        0x9FAB0D1A: (None, "auth_reset_authorizations", None),  # -1616179942
        0x03C51564: (None, "auth_send_call_v_0_1_317"),  # 63247716
        0xA677244F: (None, "auth_send_code", None),  # -1502141361
        0x768D5F4D: (None, "auth_send_code_v_0_1_317"),  # 1988976461
        0x771C1D97: (None, "auth_send_invites_v_0_1_317"),  # 1998331287
        0x5E002502: (None, "auth_sent_code", None),  # 1577067778
        0x38FAAB5F: (None, "auth_sent_code_v_5_6_2", None),  # 955951967
        0x2215BCBD: (None, "auth_sent_code_v_0_1_317"),  # 571849917
        0x3DBB5986: (None, "auth_sent_code_type_app", None),  # 1035688326
        0x5353E5A7: (None, "auth_sent_code_type_call", None),  # 1398007207
        0xAB03C6D9: (None, "auth_sent_code_type_flash_call", None),  # -1425815847
        0xC000BBA2: (None, "auth_sent_code_type_sms", None),  # -1073693790
        0xBCD51581: (None, "auth_sign_in", None),  # -1126886015
        0x80EEE427: (None, "auth_sign_up", None),  # -2131827673
        0x1B067634: (None, "auth_sign_up_v_5_6_2", None),  # 453408308
        0xAD01D61D: (None, "authorization", None),  # -1392388579
        0xE04232F3: (None, "auto_download_settings", None),  # -532532493
        0xD246FD47: (None, "auto_download_settings_v_5_6_2", None),  # -767099577
        0xA7EFF811: (None, "bad_msg_notification_v_0_1_317"),  # -1477445615
        0xEDAB447B: (None, "bad_server_salt_v_0_1_317"),  # -307542917
        0xF568028A: (None, "bank_card_open_url", None),  # -177732982
        0x5B11125A: (base_theme_arctic_struct, "base_theme_arctic", None),  # 1527845466
        0xC3A12462: (
            base_theme_classic_struct,
            "base_theme_classic",
            None,
        ),  # -1012849566
        0xFBD81688: (base_theme_day_struct, "base_theme_day", None),  # -69724536
        0xB7B31EA8: (base_theme_night_struct, "base_theme_night", None),  # -1212997976
        0x6D5F77EE: (base_theme_tinted_struct, "base_theme_tinted", None),  # 1834973166
        0xBC799737: (None, "bool_false", None),  # -1132882121 [implemented]
        0x997275B5: (None, "bool_true", None),  # -1720552011 [implemented]
        0xC27AC8C7: (bot_command_struct, "bot_command", None),  # -1032140601
        0x98E81D3A: (bot_info_struct, "bot_info", None),  # -1729618630
        0xBB2E37CE: (
            bot_info_empty_layer48_struct,
            "bot_info_empty_layer48",
            None,
        ),  # -1154598962
        0x09CF585D: (bot_info_layer48_struct, "bot_info_layer48", None),  # 164583517
        0x17DB940B: (None, "bot_inline_media_result", None),  # 400266251
        0x764CF810: (None, "bot_inline_message_media_auto", None),  # 1984755728
        0x0A74B15B: (None, "bot_inline_message_media_auto_layer74", None),  # 175419739
        0x18D1CDC2: (None, "bot_inline_message_media_contact", None),  # 416402882
        0x35EDB4D4: (
            None,
            "bot_inline_message_media_contact_layer81",
            None,
        ),  # 904770772
        0xB722DE65: (None, "bot_inline_message_media_geo", None),  # -1222451611
        0x3A8FD8B8: (None, "bot_inline_message_media_geo_layer71", None),  # 982505656
        0x8A86659C: (None, "bot_inline_message_media_venue", None),  # -1970903652
        0x4366232E: (
            None,
            "bot_inline_message_media_venue_layer77",
            None,
        ),  # 1130767150
        0x8C7F65E2: (None, "bot_inline_message_text", None),  # -1937807902
        0x11965F3A: (None, "bot_inline_result", None),  # 295067450
        0xD31A961E: (channel_struct, "channel", None),  # -753232354
        0x3B5A3E40: (None, "channel_admin_log_event", None),  # 995769920
        0x55188A2E: (
            None,
            "channel_admin_log_event_action_change_about",
            None,
        ),  # 1427671598
        0xA26F881B: (
            None,
            "channel_admin_log_event_action_change_linked_chat",
            None,
        ),  # -1569748965
        0x0E6B76AE: (
            None,
            "channel_admin_log_event_action_change_location",
            None,
        ),  # 241923758
        0x434BD2AF: (None, "channel_admin_log_event_action_change_photo"),  # 1129042607
        0xB82F55C3: (
            None,
            "channel_admin_log_event_action_change_photo_v_5_5_0",
            None,
        ),  # -1204857405
        0xB1C3CAA7: (
            None,
            "channel_admin_log_event_action_change_sticker_set",
            None,
        ),  # -1312568665
        0xE6DFB825: (
            None,
            "channel_admin_log_event_action_change_title",
            None,
        ),  # -421545947
        0x6A4AFC38: (
            None,
            "channel_admin_log_event_action_change_username",
            None,
        ),  # 1783299128
        0x2DF5FC0A: (
            None,
            "channel_admin_log_event_action_default_banned_rights",
            None,
        ),  # 771095562
        0x42E047BB: (
            None,
            "channel_admin_log_event_action_delete_message",
            None,
        ),  # 1121994683
        0x709B2405: (
            None,
            "channel_admin_log_event_action_edit_message",
            None,
        ),  # 1889215493
        0xE31C34D8: (
            None,
            "channel_admin_log_event_action_participant_invite",
            None,
        ),  # -484690728
        0x183040D3: (
            None,
            "channel_admin_log_event_action_participant_join",
            None,
        ),  # 405815507
        0xF89777F2: (
            None,
            "channel_admin_log_event_action_participant_leave",
            None,
        ),  # -124291086
        0xD5676710: (
            None,
            "channel_admin_log_event_action_participant_toggle_admin",
            None,
        ),  # -714643696
        0xE6D83D7E: (
            None,
            "channel_admin_log_event_action_participant_toggle_ban",
            None,
        ),  # -422036098
        0x8F079643: (
            None,
            "channel_admin_log_event_action_stop_poll",
            None,
        ),  # -1895328189
        0x1B7907AE: (
            None,
            "channel_admin_log_event_action_toggle_invites",
            None,
        ),  # 460916654
        0x5F5C95F1: (
            None,
            "channel_admin_log_event_action_toggle_pre_history_hidden",
            None,
        ),  # 1599903217
        0x26AE0971: (
            None,
            "channel_admin_log_event_action_toggle_signatures",
            None,
        ),  # 648939889
        0x53909779: (
            None,
            "channel_admin_log_event_action_toggle_slow_mode",
            None,
        ),  # 1401984889
        0xE9E82C18: (
            None,
            "channel_admin_log_event_action_update_pinned",
            None,
        ),  # -370660328
        0xEA107AE4: (None, "channel_admin_log_events_filter", None),  # -368018716
        0x5D7CEBA5: (
            channel_admin_rights_layer92_struct,
            "channel_admin_rights_layer92",
            None,
        ),  # 1568467877
        0x58CF4249: (
            channel_banned_rights_layer92_struct,
            "channel_banned_rights_layer92",
            None,
        ),  # 1489977929
        0x289DA732: (channel_forbidden_struct, "channel_forbidden", None),  # 681420594
        0x2D85832C: (
            channel_forbidden_layer52_struct,
            "channel_forbidden_layer52",
            None,
        ),  # 763724588
        0x8537784F: (
            channel_forbidden_layer67_struct,
            "channel_forbidden_layer67",
            None,
        ),  # -2059962289
        0xF0E6672A: (None, "channel_full", None),  # -253335766
        0x9E341DDF: (None, "channel_full_layer48", None),  # -1640751649
        0x97BEE562: (None, "channel_full_layer52", None),  # -1749097118
        0xC3D5512F: (None, "channel_full_layer67", None),  # -1009430225
        0x95CB5F57: (None, "channel_full_layer70", None),  # -1781833897
        0x17F45FCF: (None, "channel_full_layer71", None),  # 401891279
        0x76AF5481: (None, "channel_full_layer72", None),  # 1991201921
        0xCBB62890: (None, "channel_full_layer89", None),  # -877254512
        0x1C87A71A: (None, "channel_full_layer98", None),  # 478652186
        0x03648977: (None, "channel_full_layer99", None),  # 56920439
        0x9882E516: (None, "channel_full_layer101", None),  # -1736252138
        0x10916653: (None, "channel_full_layer103", None),  # 277964371
        0x2D895C74: (None, "channel_full_layer110", None),  # 763976820
        0xFAB31AA3: (None, "channel_full_old", None),  # -88925533
        0x209B82DB: (None, "channel_location", None),  # 547062491
        0xBFB5AD8B: (None, "channel_location_empty", None),  # -1078612597
        0x630E61BE: (None, "chat_full_v_0_1_317"),  # 1661886910
        0xCD77D957: (None, "channel_messages_filter", None),  # -847783593
        0x94D42EE7: (None, "channel_messages_filter_empty", None),  # -1798033689
        0x15EBAC1D: (None, "channel_participant", None),  # 367766557
        0xCCBEBBAF: (None, "channel_participant_admin", None),  # -859915345
        0x5DAA6E23: (None, "channel_participant_admin_layer103", None),  # 1571450403
        0xA82FA898: (None, "channel_participant_admin_layer92", None),  # -1473271656
        0x1C0FACAF: (None, "channel_participant_banned", None),  # 470789295
        0x222C1886: (None, "channel_participant_banned_layer92", None),  # 573315206
        0x808D15A4: (None, "channel_participant_creator", None),  # -2138237532
        0xE3E2E1F9: (None, "channel_participant_creator_layer103", None),  # -471670279
        0x98192D61: (None, "channel_participant_editor_layer67", None),  # -1743180447
        0x8CC5E69A: (None, "channel_participant_kicked_layer67", None),  # -1933187430
        0x91057FEF: (
            None,
            "channel_participant_moderator_layer67",
            None,
        ),  # -1861910545
        0xA3289A6D: (None, "channel_participant_self", None),  # -1557620115
        0xB4608969: (None, "channel_participants_admins", None),  # -1268741783
        0x1427A5E1: (None, "channel_participants_banned", None),  # 338142689
        0xB0D1865B: (None, "channel_participants_bots", None),  # -1328445861
        0xBB6AE88D: (None, "channel_participants_contacts", None),  # -1150621555
        0xA3B54985: (None, "channel_participants_kicked", None),  # -1548400251
        0xDE3F3C79: (None, "channel_participants_recent", None),  # -566281095
        0x0656AC4B: (None, "channel_participants_search", None),  # 106343499
        0x4DF30834: (channel_layer104_struct, "channel_layer104", None),  # 1307772980
        0x4B1B7506: (channel_layer48_struct, "channel_layer48", None),  # 1260090630
        0xA14DCA52: (channel_layer67_struct, "channel_layer67", None),  # -1588737454
        0x0CB44B1C: (channel_layer72_struct, "channel_layer72", None),  # 213142300
        0x450B7115: (channel_layer77_struct, "channel_layer77", None),  # 1158377749
        0xC88974AC: (channel_layer92_struct, "channel_layer92", None),  # -930515796
        0x678E9587: (channel_old_struct, "channel_old", None),  # 1737397639
        0xED8AF74D: (None, "channels_admin_log_results", None),  # -309659827
        0xD0D9B163: (None, "channels_channel_participant", None),  # -791039645
        0xF56EE2A8: (None, "channels_channel_participants", None),  # -177282392
        0xF0173FE9: (
            None,
            "channels_channel_participants_not_modified",
            None,
        ),  # -266911767
        0x10E6BD2C: (None, "channels_check_username", None),  # 283557164
        0x3D5FB10F: (None, "channels_create_channel", None),  # 1029681423
        0xF4893D7F: (None, "channels_create_channel_v_5_6_2", None),  # -192332417
        0xC0111FE3: (None, "channels_delete_channel", None),  # -1072619549
        0xAF369D42: (None, "channels_delete_history", None),  # -1355375294
        0x84C1FD4E: (None, "channels_delete_messages", None),  # -2067661490
        0xD10DD71B: (None, "channels_delete_user_history", None),  # -787622117
        0xD33C8902: (None, "channels_edit_admin", None),  # -751007486
        0x70F893BA: (None, "channels_edit_admin_v_5_6_2", None),  # 1895338938
        0x72796912: (None, "channels_edit_banned", None),  # 1920559378
        0x8F38CD1F: (None, "channels_edit_creator", None),  # -1892102881
        0x58E63F6D: (None, "channels_edit_location", None),  # 1491484525
        0xF12E57C9: (None, "channels_edit_photo", None),  # -248621111
        0x566DECD0: (None, "channels_edit_title", None),  # 1450044624
        0xC846D22D: (None, "channels_export_message_link", None),  # -934882771
        0x33DDF480: (None, "channels_get_admin_log", None),  # 870184064
        0xF8B036AF: (None, "channels_get_admined_public_channels", None),  # -122669393
        0x8D8D82D7: (
            None,
            "channels_get_admined_public_channels_v_5_6_2",
            None,
        ),  # -1920105769
        0x0A7F6BBB: (None, "channels_get_channels", None),  # 176122811
        0x08736A09: (None, "channels_get_full_channel", None),  # 141781513
        0xF5DAD378: (None, "channels_get_groups_for_discussion", None),  # -170208392
        0x11E831EE: (None, "channels_get_inactive_channels", None),  # 300429806
        0x93D7B347: (None, "channels_get_messages", None),  # -1814580409
        0x546DD7A6: (None, "channels_get_participant", None),  # 1416484774
        0x123E05E9: (None, "channels_get_participants", None),  # 306054633
        0x199F3A6C: (None, "channels_invite_to_channel", None),  # 429865580
        0x24B524C5: (None, "channels_join_channel", None),  # 615851205
        0xF836AA95: (None, "channels_leave_channel", None),  # -130635115
        0xCC104937: (None, "channels_read_history", None),  # -871347913
        0xEAB5DC38: (None, "channels_read_message_contents", None),  # -357180360
        0xFE087810: (None, "channels_report_spam", None),  # -32999408
        0x43A0A7E2: (None, "channels_search_posts", None),  # 1134602210
        0x40582BB2: (None, "channels_set_discussion_group", None),  # 1079520178
        0xEA8CA4F9: (None, "channels_set_stickers", None),  # -359881479
        0xEABBB94C: (None, "channels_toggle_pre_history_hidden", None),  # -356796084
        0x1F69B606: (None, "channels_toggle_signatures", None),  # 527021574
        0xEDD49EF0: (None, "channels_toggle_slow_mode", None),  # -304832784
        0x3514B3DE: (None, "channels_update_username", None),  # 890549214
        0x3BDA1BDE: (chat_struct, "chat", None),  # 1004149726
        0x5FB224D5: (chat_admin_rights_struct, "chat_admin_rights", None),  # 1605510357
        0x9F120418: (
            chat_banned_rights_struct,
            "chat_banned_rights",
            None,
        ),  # -1626209256
        # 0xc8d7493e: (None, 'chat_channel_participant', None),  # -925415106
        0x9BA2D800: (chat_empty_struct, "chat_empty", None),  # -1683826688
        0x07328BDB: (chat_forbidden_struct, "chat_forbidden", None),  # 120753115
        0xFB0CCC41: (
            chat_forbidden_old_struct,
            "chat_forbidden_old",
            None,
        ),  # -83047359
        0x1B7C9DB3: (None, "chat_full", None),  # 461151667
        0x2E02A614: (None, "chat_full_layer87", None),  # 771925524
        0xEDD2A791: (None, "chat_full_layer92", None),  # -304961647
        0x22A235DA: (None, "chat_full_layer98", None),  # 581055962
        0xDFC2F58E: (None, "chat_invite", None),  # -540871282
        0x5A686D7C: (None, "chat_invite_already", None),  # 1516793212
        0x69DF3769: (None, "chat_invite_empty", None),  # 1776236393
        0xFC2E05BC: (None, "chat_invite_exported", None),  # -64092740
        0x61695CB0: (None, "chat_invite_peek", None),  # 1634294960
        0xDB74F558: (None, "chat_invite_v_5_5_0", None),  # -613092008
        0xD91CDD54: (chat_layer92_struct, "chat_layer92", None),  # -652419756
        0x3631CF4C: (None, "chat_located", None),  # 909233996
        0xF041E250: (None, "chat_onlines", None),  # -264117680
        # Note the very same signature means 'chat_channel_participant' too.
        0xC8D7493E: (None, "chat_participant", None),  # -925415106
        0xE2D6E436: (None, "chat_participant_admin", None),  # -489233354
        0xDA13538A: (None, "chat_participant_creator", None),  # -636267638
        0x3F460FED: (None, "chat_participants", None),  # 1061556205
        0xFC900C2B: (None, "chat_participants_forbidden", None),  # -57668565
        0x0FD2BB8A: (None, "chat_participants_forbidden_old", None),  # 265468810
        0x7841B415: (None, "chat_participants_old", None),  # 2017571861
        0xD20B9F3C: (chat_photo_struct, "chat_photo", None),  # -770990276
        0x475CDBD5: (chat_photo_layer115_struct, "chat_photo_layer115"),  # 1197267925
        0x6153276A: (
            chat_photo_layer97_struct,
            "chat_photo_layer97",
            None,
        ),  # 1632839530
        0x37C1011C: (chat_photo_empty_struct, "chat_photo_empty", None),  # 935395612
        0x6E9C9BC7: (chat_old_struct, "chat_old", None),  # 1855757255
        0x7312BC48: (chat_old2_struct, "chat_old2", None),  # 1930607688
        0x6643B654: (None, "client_dh_inner_data_v_0_1_317"),  # 1715713620
        0xDEBEBE83: (None, "code_settings", None),  # -557924733
        0x302F59F3: (None, "code_settings_v_5_6_2", None),  # 808409587
        0x330B4067: (None, "config", None),  # 856375399
        0x232D5905: (None, "config_v_0_1_317"),  # 590174469
        0xE6CA25F6: (None, "config_v_5_5_0", None),  # -422959626
        0xF911C994: (None, "contact", None),  # -116274796
        0x561BC879: (None, "contact_blocked", None),  # 1444661369
        0xEA879F95: (None, "contact_found", None),  # -360210539
        0xD502C2D0: (
            contact_link_contact_struct,
            "contact_link_contact",
            None,
        ),  # -721239344
        0x268F3F59: (
            contact_link_has_phone_struct,
            "contact_link_has_phone",
            None,
        ),  # 646922073
        0xFEEDD3AD: (contact_link_none_struct, "contact_link_none", None),  # -17968211
        0x5F4F9247: (
            contact_link_unknown_struct,
            "contact_link_unknown",
            None,
        ),  # 1599050311
        0xD3680C61: (None, "contact_status", None),  # -748155807
        0xAA77B873: (None, "contact_status_v_0_1_317"),  # -1434994573
        0x3DE191A1: (None, "contact_suggested_v_0_1_317"),  # 1038193057
        0xF831A20F: (None, "contacts_accept_contact", None),  # -130964977
        0xE8F463D0: (None, "contacts_add_contact", None),  # -386636848
        0x332B49FC: (None, "contacts_block", None),  # 858475004
        0x1C138D15: (None, "contacts_blocked", None),  # 471043349
        0x900802A1: (None, "contacts_blocked_slice", None),  # -1878523231
        0xEAE87E42: (None, "contacts_contacts", None),  # -353862078
        0x6F8B8CB2: (None, "contacts_contacts_v_0_1_317"),  # 1871416498
        0xB74BA9D2: (None, "contacts_contacts_not_modified", None),  # -1219778094
        0x1013FD9E: (None, "contacts_delete_by_phones", None),  # 269745566
        0x8E953744: (None, "contacts_delete_contact", None),  # -1902823612
        0x096A0E00: (None, "contacts_delete_contacts", None),  # 157945344
        0x59AB389E: (None, "contacts_delete_contacts_v_5_6_2", None),  # 1504393374
        0x84E53737: (None, "contacts_export_card", None),  # -2065352905
        0x1BEA8CE1: (None, "contacts_foreign_link_mutual_v_0_1_317"),  # 468356321
        0xA7801F47: (None, "contacts_foreign_link_requested_v_0_1_317"),  # -1484775609
        0x133421F8: (None, "contacts_foreign_link_unknown_v_0_1_317"),  # 322183672
        0xB3134D9D: (None, "contacts_found", None),  # -1290580579
        0x0566000E: (None, "contacts_found_v_0_1_317"),  # 90570766
        0xF57C350F: (None, "contacts_get_blocked", None),  # -176409329
        0xC023849F: (None, "contacts_get_contacts", None),  # -1071414113
        0x22C6AA08: (None, "contacts_get_contacts_v_0_1_317"),  # 583445000
        0xD348BC44: (None, "contacts_get_located", None),  # -750207932
        0xC4A353EE: (None, "contacts_get_statuses", None),  # -995929106
        0xCD773428: (None, "contacts_get_suggested_v_0_1_317"),  # -847825880
        0xD4982DB5: (None, "contacts_get_top_peers", None),  # -728224331
        0x4FE196FE: (None, "contacts_import_card", None),  # 1340184318
        0x2C800BE5: (None, "contacts_import_contacts", None),  # 746589157
        0xDA30B32D: (None, "contacts_import_contacts_v_0_1_317"),  # -634342611
        0x77D01C3B: (None, "contacts_imported_contacts", None),  # 2010127419
        0xD1CD0A4C: (None, "contacts_imported_contacts_v_0_1_317"),  # -775091636
        0x3ACE484C: (
            contacts_link_layer101_struct,
            "contacts_link_layer101",
            None,
        ),  # 986597452
        0xECCEA3F5: (None, "contacts_link_v_0_317"),  # -322001931
        0xC240EBD9: (None, "contacts_my_link_contact_v_0_1_317"),  # -1035932711
        0xD22A1C60: (None, "contacts_my_link_empty_v_0_1_317"),  # -768992160
        0x6C69EFEE: (None, "contacts_my_link_requested_v_0_1_317"),  # 1818882030
        0x879537F1: (None, "contacts_reset_saved", None),  # -2020263951
        0x1AE373AC: (None, "contacts_reset_top_peer_rating", None),  # 451113900
        0xF93CCBA3: (None, "contacts_resolve_username", None),  # -113456221
        0x7F077AD9: (None, "contacts_resolved_peer", None),  # 2131196633
        0x11F812D8: (None, "contacts_search", None),  # 301470424
        0x5649DCC5: (None, "contacts_suggested_v_0_1_317"),  # 1447681221
        0x8514BDDA: (None, "contacts_toggle_top_peers", None),  # -2062238246
        0x70B772A8: (None, "contacts_top_peers", None),  # 1891070632
        0xB52C939D: (None, "contacts_top_peers_disabled", None),  # -1255369827
        0xDE266EF5: (None, "contacts_top_peers_not_modified", None),  # -567906571
        0xE54100BD: (None, "contacts_unblock", None),  # -448724803
        0x7D748D04: (None, "data_json", None),  # 2104790276
        0x18B7A10D: (None, "dc_option", None),  # 414687501
        0x2EC2A43C: (None, "dc_option_v_0_1_317"),  # 784507964
        0x91CC4674: (None, "decrypted_message", None),  # -1848883596
        0xDD05EC6B: (
            decrypted_message_action_abort_key_struct,
            "decrypted_message_action_abort_key",
            None,
        ),  # -586814357
        0x6FE1735B: (
            decrypted_message_action_accept_key_struct,
            "decrypted_message_action_accept_key",
            None,
        ),  # 1877046107
        0xEC2E0B9B: (
            decrypted_message_action_commit_key_struct,
            "decrypted_message_action_commit_key",
            None,
        ),  # -332526693
        0x65614304: (
            decrypted_message_action_delete_messages_struct,
            "decrypted_message_action_delete_messages",
            None,
        ),  # 1700872964
        0x6719E45C: (
            decrypted_message_action_flush_history_struct,
            "decrypted_message_action_flush_history",
            None,
        ),  # 1729750108
        0xA82FDD63: (
            decrypted_message_action_noop_struct,
            "decrypted_message_action_noop",
            None,
        ),  # -1473258141
        0xF3048883: (
            decrypted_message_action_notify_layer_struct,
            "decrypted_message_action_notify_layer",
            None,
        ),  # -217806717
        0x0C4F40BE: (
            decrypted_message_action_read_messages_struct,
            "decrypted_message_action_read_messages",
            None,
        ),  # 206520510
        0xF3C9611B: (
            decrypted_message_action_request_key_struct,
            "decrypted_message_action_request_key",
            None,
        ),  # -204906213
        0x511110B0: (
            decrypted_message_action_resend_struct,
            "decrypted_message_action_resend",
            None,
        ),  # 1360072880
        0x8AC1F475: (
            decrypted_message_action_screenshot_messages_struct,
            "decrypted_message_action_screenshot_messages",
            None,
        ),  # -1967000459
        0xA1733AEC: (
            decrypted_message_action_set_message_ttl_struct,
            "decrypted_message_action_set_message_ttl",
            None,
        ),  # -1586283796
        0xCCB27641: (
            decrypted_message_action_typing_struct,
            "decrypted_message_action_typing",
            None,
        ),  # -860719551
        0x1BE31789: (None, "decrypted_message_layer", None),  # 467867529
        0x99A438CF: (None, "decrypted_message_layer_v_0_1_317"),  # -1717290801
        0x57E0A9CB: (None, "decrypted_message_media_audio", None),  # 1474341323
        0x6080758F: (None, "decrypted_message_media_audio_layer8", None),  # 1619031439
        0x588A0A97: (None, "decrypted_message_media_contact", None),  # 1485441687
        0x7AFE8AE2: (None, "decrypted_message_media_document", None),  # 2063502050
        0xB095434B: (
            None,
            "decrypted_message_media_document_layer8",
            None,
        ),  # -1332395189
        0x089F5C4A: (None, "decrypted_message_media_empty", None),  # 144661578
        0xFA95B0DD: (
            None,
            "decrypted_message_media_external_document",
            None,
        ),  # -90853155
        0x35480A59: (None, "decrypted_message_media_geo_point", None),  # 893913689
        0xF1FA8D78: (None, "decrypted_message_media_photo", None),  # -235238024
        0x32798A8C: (None, "decrypted_message_media_photo_layer8", None),  # 846826124
        0x8A0DF56F: (None, "decrypted_message_media_venue", None),  # -1978796689
        0x970C8C0E: (None, "decrypted_message_media_video", None),  # -1760785394
        0x524A415D: (None, "decrypted_message_media_video_layer17", None),  # 1380598109
        0x4CEE6EF3: (None, "decrypted_message_media_video_layer8", None),  # 1290694387
        0xE50511D8: (None, "decrypted_message_media_web_page", None),  # -452652584
        0x73164160: (None, "decrypted_message_service", None),  # 1930838368
        0xAA48327D: (None, "decrypted_message_service_layer8", None),  # -1438109059
        0x204D3878: (None, "decrypted_message_layer17", None),  # 541931640
        0x36B091DE: (None, "decrypted_message_layer45", None),  # 917541342
        0x1F814F1F: (None, "decrypted_message_layer8", None),  # 528568095
        0xE7512126: (None, "destroy_session_v_0_1_317"),  # -414113498
        0xA13DC52F: (None, "destroy_sessions_v_0_1_317"),  # -1589787345
        0x62D350C9: (None, "destroy_session_none_v_0_1_317"),  # 1658015945
        0xE22045FC: (None, "destroy_session_ok_v_0_1_317"),  # -501201412
        0xFB95ABCD: (None, "destroy_sessions_res_v_0_1_317"),  # -74077235
        0xA69DAE02: (None, "dh_gen_fail_v_0_1_317"),  # -1499615742
        0x3BCBF734: (None, "dh_gen_ok_v_0_1_317"),  # 1003222836
        0x46DC1FB9: (None, "dh_gen_retry_v_0_1_317"),  # 1188831161
        0x2C171F72: (None, "dialog", None),  # 739712882
        0x7438F7E8: (None, "dialog_filter", None),  # 1949890536
        0x77744D4A: (None, "dialog_filter_suggested", None),  # 2004110666
        0x14F9162C: (None, "dialog_filter_v_5_15_0", None),  # 351868460
        0x71BD134C: (None, "dialog_folder", None),  # 1908216652
        0x214A8CDF: (None, "dialog_v_0_1_317"),  # 558533855
        0xE4DEF5DB: (None, "dialog_v_5_5_0", None),  # -45515011
        0xE56DBF05: (None, "dialog_peer", None),  # -445792507
        0xDA429411: (None, "dialog_peer_feed_v_5_5_0", None),  # -633170927
        0x514519E2: (None, "dialog_peer_folder", None),  # 1363483106
        0x1E87342B: (document_struct, "document", None),  # 512177195
        0x11B58939: (
            document_attribute_animated_struct,
            "document_attribute_animated",
            None,
        ),  # 297109817
        0x9852F9C6: (
            document_attribute_audio_struct,
            "document_attribute_audio",
            None,
        ),  # -1739392570
        0xDED218E0: (
            document_attribute_audio_layer45_struct,
            "document_attribute_audio_layer45",
            None,
        ),  # -556656416
        0x051448E5: (
            document_attribute_audio_old_struct,
            "document_attribute_audio_old",
            None,
        ),  # 85215461
        0x15590068: (
            document_attribute_filename_struct,
            "document_attribute_filename",
            None,
        ),  # 358154344
        0x9801D2F7: (
            document_attribute_has_stickers_struct,
            "document_attribute_has_stickers",
            None,
        ),  # -1744710921
        0x6C37C15C: (
            document_attribute_image_size_struct,
            "document_attribute_image_size",
            None,
        ),  # 1815593308
        0x6319D612: (
            document_attribute_sticker_struct,
            "document_attribute_sticker",
            None,
        ),  # 1662637586
        0x3A556302: (
            document_attribute_sticker_layer55_struct,
            "document_attribute_sticker_layer55",
            None,
        ),  # 978674434
        0xFB0A5727: (
            document_attribute_sticker_old_struct,
            "document_attribute_sticker_old",
            None,
        ),  # -83208409
        0x994C9882: (
            document_attribute_sticker_old2_struct,
            "document_attribute_sticker_old2",
            None,
        ),  # -1723033470
        0x0EF02CE6: (
            document_attribute_video_struct,
            "document_attribute_video",
            None,
        ),  # 250621158
        0x5910CCCB: (
            document_attribute_video_layer65_struct,
            "document_attribute_video_layer65",
            None,
        ),  # 1494273227
        0x36F8C871: (document_empty_struct, "document_empty", None),  # 922273905
        0x55555558: (
            document_encrypted_struct,
            "document_encrypted",
            None,
        ),  # 1431655768
        0x55555556: (
            document_encrypted_old_struct,
            "document_encrypted_old",
            None,
        ),  # 1431655766
        0x9BA29CC1: (
            document_layer113_struct,
            "document_layer113",
            None,
        ),  # -1683841855
        0xF9A39F4F: (document_layer53_struct, "document_layer53", None),  # -106717361
        0x87232BC7: (document_layer82_struct, "document_layer82", None),  # -2027738169
        0x59534E4C: (document_layer92_struct, "document_layer92", None),  # 1498631756
        0x9EFC6326: (document_old_struct, "document_old", None),  # -1627626714
        0xFD8E711F: (None, "draft_message", None),  # -40996577
        0x1B0C841A: (None, "draft_message_empty", None),  # 453805082
        0xBA4BAEC5: (None, "draft_message_empty_layer81", None),  # -1169445179
        0xD5B3B9F9: (None, "emoji_keyword", None),  # -709641735
        0x236DF622: (None, "emoji_keyword_deleted", None),  # 594408994
        0x5CC761BD: (None, "emoji_keywords_difference", None),  # 1556570557
        0xB3FB5361: (None, "emoji_language", None),  # -1275374751
        0xA575739D: (None, "emoji_url", None),  # -1519029347
        0xFA56CE36: (encrypted_chat_struct, "encrypted_chat", None),  # -94974410
        0x13D6DD27: (
            encrypted_chat_discarded_struct,
            "encrypted_chat_discarded",
            None,
        ),  # 332848423
        0xAB7EC0A0: (
            encrypted_chat_empty_struct,
            "encrypted_chat_empty",
            None,
        ),  # -1417756512
        0x62718A82: (
            encrypted_chat_requested_struct,
            "encrypted_chat_requested",
            None,
        ),  # 1651608194
        0xC878527E: (
            encrypted_chat_requested_layer115_struct,
            "encrypted_chat_requested_layer115",
            None,
        ),  # -931638658
        0xFDA9A7B7: (
            encrypted_chat_requested_old_struct,
            "encrypted_chat_requested_old",
            None,
        ),  # -39213129
        0x3BF703DC: (
            encrypted_chat_waiting_struct,
            "encrypted_chat_waiting",
            None,
        ),  # 1006044124
        0x6601D14F: (
            encrypted_chat_old_struct,
            "encrypted_chat_old",
            None,
        ),  # 1711395151
        0x4A70994C: (None, "encrypted_file", None),  # 1248893260
        0xC21F497E: (None, "encrypted_file_empty", None),  # -1038136962
        0xED18C118: (None, "encrypted_message", None),  # -317144808
        0x23734B06: (None, "encrypted_message_service", None),  # 594758406
        0xC4B9F9BB: (None, "error", None),  # -994444869
        0x5DAB1AF4: (None, "exported_message_link", None),  # 1571494644
        0x55555554: (
            file_encrypted_location_struct,
            "file_encrypted_location",
            None,
        ),  # 1431655764
        0x6242C773: (None, "file_hash", None),  # 1648543603
        0xBC7FC6CD: (
            file_location_to_be_deprecated_struct,
            "file_location_to_be_deprecated",
            None,
        ),  # -1132476723
        0x53D69076: (
            file_location_layer82_struct,
            "file_location_layer82",
            None,
        ),  # 1406570614
        0x091D11EB: (
            file_location_layer97_struct,
            "file_location_layer97",
            None,
        ),  # 152900075
        0x7C596B46: (
            file_location_unavailable_struct,
            "file_location_unavailable",
            None,
        ),  # 2086234950
        0xFF544E65: (None, "folder", None),  # -11252123
        0xE9BAA668: (None, "folder_peer", None),  # -373643672
        0x1C295881: (None, "folders_delete_folder", None),  # 472471681
        0x6847D0AB: (None, "folders_edit_peer_folders", None),  # 1749536939
        0x162ECC1F: (None, "found_gif", None),  # 372165663
        0x9C750409: (None, "found_gif_cached", None),  # -1670052855
        0x0949D9DC: (None, "future_salt_v_0_1_317"),  # 155834844
        0xAE500895: (None, "futuresalts_v_0_1_317"),  # -1370486635
        0xBDF9653B: (game_struct, "game", None),  # -1107729093
        0x75EAEA5A: (None, "geo_chat_v_0_1_317"),  # 1978329690
        0x4505F8E1: (None, "geo_chat_message_v_0_1_317"),  # 1158019297
        0x60311A9B: (None, "geo_chat_message_empty_v_0_1_317"),  # 1613830811
        0xD34FA24E: (None, "geo_chat_message_service_v_0_1_317"),  # -749755826
        0x0296F104: (geo_point_struct, "geo_point", None),  # 43446532
        0x1117DD5F: (geo_point_empty_struct, "geo_point_empty", None),  # 286776671
        0x2049D70C: (geo_point_layer81_struct, "geo_point_layer81", None),  # 541710092
        0x55B3E8FB: (None, "geochats_checkin_v_0_1_317"),  # 1437853947
        0x0E092E16: (None, "geochats_create_geo_chat_v_0_1_317"),  # 235482646
        0x35D81A95: (None, "geochats_edit_chat_photo_v_0_1_317"),  # 903355029
        0x4C8E2273: (None, "geochats_edit_chat_title_v_0_1_317"),  # 1284383347
        0x6722DD6F: (None, "geochats_get_full_chat_v_0_1_317"),  # 1730338159
        0xB53F7A68: (None, "geochats_get_history_v_0_1_317"),  # -1254131096
        0x7F192D8F: (None, "geochats_get_located_v_0_1_317"),  # 2132356495
        0xE1427E6F: (None, "geochats_get_recents_v_0_1_317"),  # -515735953
        0x48FEB267: (None, "geochats_located_v_0_1_317"),  # 1224651367
        0xD1526DB1: (None, "geochats_messages_v_0_1_317"),  # -783127119
        0xBC5863E8: (None, "geochats_messages_slice_v_0_1_317"),  # -1135057944
        0xCFCDC44D: (None, "geochats_search_v_0_1_317"),  # -808598451
        0xB8F0DEFF: (None, "geochats_send_media_v_0_1_317"),  # -1192173825
        0x061B0044: (None, "geochats_send_message_v_0_1_317"),  # 102432836
        0x08B8A729: (None, "geochats_set_typing_v_0_1_317"),  # 146319145
        0x17B1578B: (None, "geochats_stated_message_v_0_1_317"),  # 397498251
        0xB921BD04: (None, "get_future_salts_v_0_1_317"),  # -1188971260
        0xBEA2F424: (None, "global_privacy_settings", None),  # -1096616924
        0x0A8F1624: (None, "group_call", None),  # 177149476
        0x40732163: (None, "group_call_connection", None),  # 1081287011
        0x7780BCB4: (None, "group_call_discarded", None),  # 2004925620
        0x589DB397: (None, "group_call_participant", None),  # 1486730135
        0x4F0B39B8: (None, "group_call_participant_admin", None),  # 1326135736
        0x377496F0: (None, "group_call_participant_invited", None),  # 930387696
        0x419B0DF2: (None, "group_call_participant_left", None),  # 1100680690
        0x6D0B1604: (None, "group_call_private", None),  # 1829443076
        0x3072CFA1: (None, "gzip_packed_v_0_1_317"),  # 812830625
        0xEE72F79A: (None, "help_accept_terms_of_service", None),  # -294455398
        0x1DA7158F: (None, "help_app_update", None),  # 497489295
        0x8987F311: (None, "help_app_update_v_0_1_317"),  # -1987579119
        0xC812AC7E: (None, "help_get_app_update_v_0_1_317"),  # -938300290
        0x6A4EE832: (None, "help_deep_link_info", None),  # 1783556146
        0x66AFA166: (None, "help_deep_link_info_empty", None),  # 1722786150
        0x077FA99F: (None, "help_dismiss_suggestion", None),  # 125807007
        0x66B91B70: (None, "help_edit_user_info", None),  # 1723407216
        0x9010EF6F: (None, "help_get_app_changelog", None),  # -1877938321
        0x98914110: (None, "help_get_app_config", None),  # -1735311088
        0x522D5A7D: (None, "help_get_app_update", None),  # 1378703997
        0xC4F9186B: (None, "help_get_config", None),  # -990308245
        0x3FEDC75F: (None, "help_get_deep_link_info", None),  # 1072547679
        0x4D392343: (None, "help_get_invite_text", None),  # 1295590211
        0xA4A95186: (None, "help_get_invite_text_v_0_1_317"),  # -1532407418
        0x1FB33026: (None, "help_get_nearest_dc", None),  # 531836966
        0xC661AD08: (None, "help_get_passport_config", None),  # -966677240
        0xC0977421: (None, "help_get_promo_data", None),  # -1063816159
        0x3D7758E1: (None, "help_get_proxy_data", None),  # 1031231713
        0x3DC0F114: (None, "help_get_recent_me_urls", None),  # 1036054804
        0x9CDF08CD: (None, "help_get_support", None),  # -1663104819
        0xD360E72C: (None, "help_get_support_name", None),  # -748624084
        0x2CA51FD1: (None, "help_get_terms_of_service_update", None),  # 749019089
        0x038A08D3: (None, "help_get_user_info", None),  # 59377875
        0x1E251C95: (None, "help_hide_promo_data", None),  # 505748629
        0x18CB9F78: (None, "help_invite_text", None),  # 415997816
        0xC45A6536: (None, "help_no_app_update", None),  # -1000708810
        0xA098D6AF: (None, "help_passport_config", None),  # -1600596305
        0xBFB9F457: (None, "help_passport_config_not_modified", None),  # -1078332329
        0x98F6AC75: (None, "help_promo_data_empty", None),  # -1728664459
        0x8C39793F: (None, "help_promo_data", None),  # -1942390465
        0xE09E1FB8: (None, "help_proxy_data_empty", None),  # -526508104
        0x2BF7EE23: (None, "help_proxy_data_promo", None),  # 737668643
        0x0E0310D7: (None, "help_recent_me_urls", None),  # 235081943
        0x6F02F748: (None, "help_save_app_log", None),  # 1862465352
        0xEC22CFCD: (None, "help_set_bot_updates_status", None),  # -333262899
        0x17C6B5F6: (None, "help_support", None),  # 398898678
        0x8C05F1C9: (None, "help_support_name", None),  # -1945767479
        0x780A0310: (None, "help_terms_of_service", None),  # 2013922064
        0x28ECF961: (None, "help_terms_of_service_update", None),  # 686618977
        0xE3309F7F: (None, "help_terms_of_service_update_empty", None),  # -483352705
        0x01EB3758: (None, "help_user_info", None),  # 32192344
        0xF3AE2EED: (None, "help_user_info_empty", None),  # -206688531
        0x58FFFCD0: (None, "high_score", None),  # 1493171408
        0x9299359F: (None, "http_wait_v_0_1_317"),  # -1835453025
        0xD0028438: (None, "imported_contact", None),  # -805141448
        0x69796DE9: (None, "init_connection_v_0_1_317"),  # 1769565673
        0x3C20629F: (None, "inline_bot_switch_p_m", None),  # 1008755359
        0x1D1B1245: (None, "input_app_event", None),  # 488313413
        0x770656A8: (None, "input_app_event_v_0_1_317"),  # 1996904104
        0x77D440FF: (None, "input_audio_v_0_1_317"),  # 2010398975
        0xD95ADC84: (None, "input_audio_empty_v_0_1_317"),  # -648356732
        0x74DC404D: (None, "input_audio_file_location_v_0_1_317"),  # 1960591437
        0x890C3D89: (None, "input_bot_inline_message_id", None),  # -1995686519
        0xAFEB712E: (input_channel_struct, "input_channel", None),  # -1343524562
        0xEE8C1E86: (
            input_channel_empty_struct,
            "input_channel_empty",
            None,
        ),  # -292807034
        0x2A286531: (None, "input_channel_from_message", None),  # 707290417
        0x8953AD37: (None, "input_chat_photo", None),  # -1991004873
        0xB2E1BF08: (None, "input_chat_photo_v_0_1_317"),  # -1293828344
        0x1CA48F57: (None, "input_chat_photo_empty", None),  # 480546647
        0xC642724E: (None, "input_chat_uploaded_photo", None),  # -968723890
        0x927C55B4: (None, "input_chat_uploaded_photo_v_5_15_0", None),  # -1837345356
        0x94254732: (None, "input_chat_uploaded_photo_v_0_1_317"),  # -1809496270
        0x9880F658: (None, "input_check_password_empty", None),  # -1736378792
        0xD27FF082: (None, "input_check_password_s_r_p", None),  # -763367294
        0xFCAAFEB7: (None, "input_dialog_peer", None),  # -55902537
        0x2C38B8CF: (None, "input_dialog_peer_feed_v_5_5_0", None),  # 741914831
        0x64600527: (None, "input_dialog_peer_folder", None),  # 1684014375
        0x1ABFB575: (None, "input_document", None),  # 448771445
        0x72F0EAAE: (None, "input_document_empty", None),  # 1928391342
        0xBAD07584: (None, "input_document_file_location", None),  # -1160743548
        0x4E45ABE9: (None, "input_document_file_location_v_0_1_317"),  # 1313188841
        0x196683D9: (None, "input_document_file_location_v_5_5_0", None),  # 426148825
        0x18798952: (None, "input_document_v_0_1_317"),  # 410618194
        0xF141B5E1: (None, "input_encrypted_chat", None),  # -247351839
        0x5A17B5E5: (None, "input_encrypted_file", None),  # 1511503333
        0x2DC173C8: (None, "input_encrypted_file_big_uploaded", None),  # 767652808
        0x1837C364: (None, "input_encrypted_file_empty", None),  # 406307684
        0xF5235D55: (None, "input_encrypted_file_location", None),  # -182231723
        0x64BD0306: (None, "input_encrypted_file_uploaded", None),  # 1690108678
        0xF52FF27F: (None, "input_file", None),  # -181407105
        0xFA4F0BB5: (None, "input_file_big", None),  # -95482955
        0xDFDAABE1: (None, "input_file_location", None),  # -539317279
        0x14637196: (None, "input_file_location_v_0_1_317"),  # 342061462
        0xFBD2C296: (None, "input_folder_peer", None),  # -70073706
        0x032C3E77: (None, "input_game_id", None),  # 53231223
        0xC331E80A: (None, "input_game_short_name", None),  # -1020139510
        0x74D456FA: (None, "input_geo_chat_v_0_1_317"),  # 1960072954
        0xF3B7ACC9: (None, "input_geo_point", None),  # -206066487
        0xE4C123D6: (None, "input_geo_point_empty", None),  # -457104426
        0xD8AA840F: (input_group_call_struct, "input_group_call", None),  # -659913713
        0xD02E7FD4: (None, "input_keyboard_button_url_auth", None),  # -802258988
        0x89938781: (None, "input_media_audio_v_0_1_317"),  # -1986820223
        0xF8AB7DFB: (None, "input_media_contact", None),  # -122978821
        0xA6E45987: (None, "input_media_contact_v_0_1_317"),  # -1494984313
        0xE66FBF7B: (None, "input_media_dice", None),  # -428884101
        0x23AB23D2: (None, "input_media_document", None),  # 598418386
        0xFB52DC99: (None, "input_media_document_external", None),  # -78455655
        0xD184E841: (None, "input_media_document_v_0_1_317"),  # -779818943
        0x9664F57F: (None, "input_media_empty", None),  # -1771768449
        0xD33F43F3: (None, "input_media_game", None),  # -750828557
        0xCE4E82FD: (None, "input_media_geo_live", None),  # -833715459
        0xF9C44144: (None, "input_media_geo_point", None),  # -104578748
        0x4843B0FD: (None, "input_media_gif_external", None),  # 1212395773
        0xB3BA0635: (None, "input_media_photo", None),  # -1279654347
        0xE5BBFE1A: (None, "input_media_photo_external", None),  # -440664550
        0x8F2AB2EC: (None, "input_media_photo_v_0_1_317"),  # -1893027092
        0x0F94E5F1: (None, "input_media_poll", None),  # 261416433
        0xABE9CA25: (None, "input_media_poll_v_5_15_0", None),  # -1410741723
        0x06B3765B: (None, "input_media_poll_v_5_6_2", None),  # 112424539
        0x61A6D436: (None, "input_media_uploaded_audio_v_0_1_317"),  # 1638323254
        0x5B38C6C1: (None, "input_media_uploaded_document", None),  # 1530447553
        0x34E794BD: (None, "input_media_uploaded_document_v_0_1_317"),  # 887592125
        0x1E287D04: (None, "input_media_uploaded_photo", None),  # 505969924
        0x2DC53A7D: (None, "input_media_uploaded_photo_v_0_1_317"),  # 767900285
        0x3E46DE5D: (
            None,
            "input_media_uploaded_thumb_document_v_0_1_317",
        ),  # 1044831837
        0xE628A145: (None, "input_media_uploaded_thumb_video_v_0_1_317"),  # -433544891
        0x4847D92A: (None, "input_media_uploaded_video_v_0_1_317"),  # 1212668202
        0xC13D1C11: (None, "input_media_venue", None),  # -1052959727
        0x7F023AE6: (None, "input_media_video_v_0_1_317"),  # 2130852582
        0x208E68C9: (
            input_message_entity_mention_name_struct,
            "input_message_entity_mention_name",
            None,
        ),  # 546203849
        0x3A20ECB8: (None, "input_messages_filter_chat_photos", None),  # 975236280
        0xE062DB83: (None, "input_messages_filter_contacts", None),  # -530392189
        0x9EDDF188: (None, "input_messages_filter_document", None),  # -1629621880
        0x57E2F66C: (None, "input_messages_filter_empty", None),  # 1474492012
        0xE7026D0D: (None, "input_messages_filter_geo", None),  # -419271411
        0xFFC86587: (None, "input_messages_filter_gif", None),  # -3644025
        0x3751B49E: (None, "input_messages_filter_music", None),  # 928101534
        0xC1F8E69A: (None, "input_messages_filter_my_mentions", None),  # -1040652646
        0x80C99768: (None, "input_messages_filter_phone_calls", None),  # -2134272152
        0x56E9F0E4: (None, "input_messages_filter_photo_video", None),  # 1458172132
        0xD95E73BB: (
            None,
            "input_messages_filter_photo_video_documents",
            None,
        ),  # -648121413
        0x9609A51C: (None, "input_messages_filter_photos", None),  # -1777752804
        0xB549DA53: (None, "input_messages_filter_round_video", None),  # -1253451181
        0x7A7C17A4: (None, "input_messages_filter_round_voice", None),  # 2054952868
        0x7EF0DD87: (None, "input_messages_filter_url", None),  # 2129714567
        0x9FC00E65: (None, "input_messages_filter_video", None),  # -1614803355
        0x50F5C392: (None, "input_messages_filter_voice", None),  # 1358283666
        0xA429B886: (None, "input_notify_all_v_0_1_317"),  # -1540769658
        0xB1DB7C7E: (None, "input_notify_broadcasts", None),  # -1311015810
        0x4A95E84E: (None, "input_notify_chats", None),  # 1251338318
        0x4D8DDEC8: (None, "input_notify_geo_chat_peer_v_0_1_317"),  # 1301143240
        0xB8BC5B0C: (None, "input_notify_peer", None),  # -1195615476
        0x193B4417: (None, "input_notify_users", None),  # 423314455
        0x3417D728: (None, "input_payment_credentials", None),  # 873977640
        0xCA05D50E: (None, "input_payment_credentials_android_pay", None),  # -905587442
        0xC10EB2CF: (None, "input_payment_credentials_saved", None),  # -1056001329
        0x20ADAEF8: (None, "input_peer_channel", None),  # 548253432
        0x9C95F7BB: (None, "input_peer_channel_from_message", None),  # -1667893317
        0x179BE863: (None, "input_peer_chat", None),  # 396093539
        0x1023DBE8: (None, "input_peer_contact_v_0_1_317"),  # 270785512
        0x7F3B18EA: (None, "input_peer_empty", None),  # 2134579434
        0x9B447325: (None, "input_peer_foreign_v_0_1_317"),  # -1690012891
        0xE86A2C74: (None, "input_peer_notify_events_all_v_0_1_317"),  # -395694988
        0xF03064D8: (None, "input_peer_notify_events_empty_v_0_1_317"),  # -265263912
        0x9C3D198E: (None, "input_peer_notify_settings", None),  # -1673717362
        0x46A2CE98: (None, "input_peer_notify_settings_v_0_1_317"),  # 1185074840
        0x27D69997: (None, "input_peer_photo_file_location", None),  # 668375447
        0x7DA07EC9: (None, "input_peer_self", None),  # 2107670217
        0x7B8E7DE6: (None, "input_peer_user", None),  # 2072935910
        0x17BAE2E6: (None, "input_peer_user_from_message", None),  # 398123750
        0x1E36FDED: (None, "input_phone_call", None),  # 506920429
        0xF392B7F4: (None, "input_phone_contact", None),  # -208488460
        0x3BB3B94A: (None, "input_photo", None),  # 1001634122
        0xD9915325: (None, "input_photo_crop_v_0_1_317"),  # -644787419
        0xADE6B004: (None, "input_photo_crop_auto_v_0_1_317"),  # -1377390588
        0x1CD7BF0D: (None, "input_photo_empty", None),  # 483901197
        0x40181FFE: (None, "input_photo_file_location", None),  # 1075322878
        0xFB95C6C4: (None, "input_photo_v_0_1_317"),  # -74070332
        0xD1219BDD: (None, "input_privacy_key_added_by_phone", None),  # -786326563
        0xBDFB0426: (None, "input_privacy_key_chat_invite", None),  # -1107622874
        0xA4DD4C08: (None, "input_privacy_key_forwards", None),  # -1529000952
        0xFABADC5F: (None, "input_privacy_key_phone_call", None),  # -88417185
        0x0352DAFA: (None, "input_privacy_key_phone_number", None),  # 55761658
        0xDB9E70D2: (None, "input_privacy_key_phone_p2_p", None),  # -610373422
        0x5719BACC: (None, "input_privacy_key_profile_photo", None),  # 1461304012
        0x4F96CB18: (None, "input_privacy_key_status_timestamp", None),  # 1335282456
        0x184B35CE: (None, "input_privacy_value_allow_all", None),  # 407582158
        0x4C81C1BA: (
            None,
            "input_privacy_value_allow_chat_participants",
            None,
        ),  # 1283572154
        0x0D09E07B: (None, "input_privacy_value_allow_contacts", None),  # 218751099
        0x131CC67F: (None, "input_privacy_value_allow_users", None),  # 320652927
        0xD66B66C9: (None, "input_privacy_value_disallow_all", None),  # -697604407
        0xD82363AF: (
            None,
            "input_privacy_value_disallow_chat_participants",
            None,
        ),  # -668769361
        0x0BA52007: (None, "input_privacy_value_disallow_contacts", None),  # 195371015
        0x90110467: (None, "input_privacy_value_disallow_users", None),  # -1877932953
        0xADF44EE3: (None, "input_report_reason_child_abuse", None),  # -1376497949
        0x9B89F93A: (None, "input_report_reason_copyright", None),  # -1685456582
        0xDBD4FEED: (None, "input_report_reason_geo_irrelevant", None),  # -606798099
        0xE1746D0A: (None, "input_report_reason_other", None),  # -512463606
        0x2E59D922: (None, "input_report_reason_pornography", None),  # 777640226
        0x58DBCAB8: (None, "input_report_reason_spam", None),  # 1490799288
        0x1E22C78D: (None, "input_report_reason_violence", None),  # 505595789
        0x5367E5BE: (None, "input_secure_file", None),  # 1399317950
        0xCBC7EE28: (None, "input_secure_file_location", None),  # -876089816
        0x3334B0F0: (None, "input_secure_file_uploaded", None),  # 859091184
        0xDB21D0A7: (None, "input_secure_value", None),  # -618540889
        0x1CC6E91F: (None, "input_single_media", None),  # 482797855
        0x028703C8: (
            input_sticker_set_animated_emoji_struct,
            "input_sticker_set_animated_emoji",
            None,
        ),  # 42402760
        0xE67F520E: (
            input_sticker_set_dice_struct,
            "input_sticker_set_dice",
            None,
        ),  # -427863538
        0xFFB62B95: (
            input_sticker_set_empty_struct,
            "input_sticker_set_empty",
            None,
        ),  # -4838507
        0x9DE7A269: (
            input_sticker_set_id_struct,
            "input_sticker_set_id",
            None,
        ),  # -1645763991
        0x861CC8A0: (
            input_sticker_set_short_name_struct,
            "input_sticker_set_short_name",
            None,
        ),  # -2044933984
        0x0DBAEAE9: (None, "input_sticker_set_thumb", None),  # 230353641
        0x0438865B: (None, "input_stickered_media_document", None),  # 70813275
        0x4A992157: (None, "input_stickered_media_photo", None),  # 1251549527
        0x3C5693E9: (None, "input_theme", None),  # 1012306921
        0xBD507CD1: (None, "input_theme_settings", None),  # -1118798639
        0xF5890DF1: (None, "input_theme_slug", None),  # -175567375
        0xD8292816: (input_user_struct, "input_user", None),  # -668391402
        0x86E94F65: (None, "input_user_contact_v_0_1_317"),  # -2031530139
        0xB98886CF: (input_user_empty_struct, "input_user_empty", None),  # -1182234929
        0x655E74FF: (None, "input_user_foreign_v_0_1_317"),  # 1700689151
        0x2D117597: (None, "input_user_from_message", None),  # 756118935
        0xF7C1B13F: (None, "input_user_self", None),  # -138301121
        0xEE579652: (None, "input_video_v_0_1_317"),  # -296249774
        0x5508EC75: (None, "input_video_empty_v_0_1_317"),  # 1426648181
        0x3D0364EC: (None, "input_video_file_location_v_0_1_317"),  # 1023632620
        0xE630B979: (None, "input_wall_paper", None),  # -433014407
        0x8427BBAC: (None, "input_wall_paper_no_file", None),  # -2077770836
        0x72091C80: (None, "input_wall_paper_slug", None),  # 1913199744
        0x9BED434D: (None, "input_web_document", None),  # -1678949555
        0x9F2221C9: (None, "input_web_file_geo_point_location", None),  # -1625153079
        0xC239D686: (None, "input_web_file_location", None),  # -1036396922
        0xC30AA358: (None, "invoice", None),  # -1022713000
        0xCB9F372D: (None, "invoke_after_msg_v_0_1_317"),  # -878758099
        0xA6B88FDF: (None, "invoke_with_layer11_v_0_1_317"),  # -1497853985
        0xF7444763: (None, "json_array", None),  # -146520221
        0xC7345E6A: (None, "json_bool", None),  # -952869270
        0x3F6D7B68: (None, "json_null", None),  # 1064139624
        0x2BE0DFA4: (None, "json_number", None),  # 736157604
        0x99C1D49D: (None, "json_object", None),  # -1715350371
        0xC0DE1BD9: (None, "json_object_value", None),  # -1059185703
        0xB71E767A: (None, "json_string", None),  # -1222740358
        0xA2FA4880: (keyboard_button_struct, "keyboard_button", None),  # -1560655744
        0xAFD93FBB: (
            keyboard_button_buy_struct,
            "keyboard_button_buy",
            None,
        ),  # -1344716869
        0x683A5E46: (
            keyboard_button_callback_struct,
            "keyboard_button_callback",
            None,
        ),  # 1748655686
        0x50F41CCF: (
            keyboard_button_game_struct,
            "keyboard_button_game",
            None,
        ),  # 1358175439
        0xFC796B3F: (
            keyboard_button_request_geo_location_struct,
            "keyboard_button_request_geo_location",
            None,
        ),  # -59151553
        0xB16A6C29: (
            keyboard_button_request_phone_struct,
            "keyboard_button_request_phone",
            None,
        ),  # -1318425559
        0xBBC7515D: (
            keyboard_button_request_poll_struct,
            "keyboard_button_request_poll",
            None,
        ),  # -1144565411
        0x77608B83: (
            keyboard_button_row_struct,
            "keyboard_button_row",
            None,
        ),  # 2002815875
        0x0568A748: (
            keyboard_button_switch_inline_struct,
            "keyboard_button_switch_inline",
            None,
        ),  # 90744648
        0x258AFF05: (
            keyboard_button_url_struct,
            "keyboard_button_url",
            None,
        ),  # 629866245
        0x10B78D29: (
            keyboard_button_url_auth_struct,
            "keyboard_button_url_auth",
            None,
        ),  # 280464681
        0xCB296BF8: (None, "labeled_price", None),  # -886477832
        0xF385C1F6: (None, "lang_pack_difference", None),  # -209337866
        0xEECA5CE3: (None, "lang_pack_language", None),  # -288727837
        0xCAD181F6: (None, "lang_pack_string", None),  # -892239370
        0x2979EEB2: (None, "lang_pack_string_deleted", None),  # 695856818
        0x6C47AC9F: (None, "lang_pack_string_pluralized", None),  # 1816636575
        0xCD984AA5: (None, "langpack_get_difference", None),  # -845657435
        0x9AB5C58E: (None, "langpack_get_lang_pack", None),  # -1699363442
        0x6A596502: (None, "langpack_get_language", None),  # 1784243458
        0x800FD57D: (None, "langpack_get_languages", None),  # -2146445955
        0x2E1EE318: (None, "langpack_get_strings", None),  # 773776152
        0xAED6DBB2: (mask_coords_struct, "mask_coords", None),  # -1361650766
        0x452C0E65: (message_struct, "message", None),  # 1160515173
        0xABE9AFFE: (
            message_action_bot_allowed_struct,
            "message_action_bot_allowed",
            None,
        ),  # -1410748418
        0x95D2AC92: (
            message_action_channel_create_struct,
            "message_action_channel_create",
            None,
        ),  # -1781355374
        0xB055EAEE: (
            message_action_channel_migrate_from_struct,
            "message_action_channel_migrate_from",
            None,
        ),  # -1336546578
        0x488A7337: (
            message_action_chat_add_user_struct,
            "message_action_chat_add_user",
            None,
        ),  # 1217033015
        0x5E3CFC4B: (
            message_action_chat_add_user_old_struct,
            "message_action_chat_add_user_old",
            None,
        ),  # 1581055051
        0xA6638B9A: (
            message_action_chat_create_struct,
            "message_action_chat_create",
            None,
        ),  # -1503425638
        0xB2AE9B0C: (
            message_action_chat_delete_user_struct,
            "message_action_chat_delete_user",
            None,
        ),  # -1297179892
        0x95E3FBEF: (
            message_action_chat_delete_photo_struct,
            "message_action_chat_delete_photo",
            None,
        ),  # -1780220945
        0x7FCB13A8: (
            message_action_chat_edit_photo_struct,
            "message_action_chat_edit_photo",
            None,
        ),  # 2144015272
        0xB5A1CE5A: (
            message_action_chat_edit_title_struct,
            "message_action_chat_edit_title",
            None,
        ),  # -1247687078
        0xF89CF5E8: (
            message_action_chat_joined_by_link_struct,
            "message_action_chat_joined_by_link",
            None,
        ),  # -123931160
        0x51BDB021: (
            message_action_chat_migrate_to_struct,
            "message_action_chat_migrate_to",
            None,
        ),  # 1371385889
        0xF3F25F76: (
            message_action_contact_sign_up_struct,
            "message_action_contact_sign_up",
            None,
        ),  # -202219658
        0x55555557: (
            message_action_created_broadcast_list_struct,
            "message_action_created_broadcast_list",
            None,
        ),  # 1431655767
        0xFAE69F56: (
            message_action_custom_action_struct,
            "message_action_custom_action",
            None,
        ),  # -85549226
        0xB6AEF7B0: (
            message_action_empty_struct,
            "message_action_empty",
            None,
        ),  # -1230047312
        0x92A72876: (
            message_action_game_score_struct,
            "message_action_game_score",
            None,
        ),  # -1834538890
        0x0C7D53DE: (None, "message_action_geo_chat_checkin_v_0_1_317"),  # 209540062
        0x6F038EBC: (None, "message_action_geo_chat_create_v_0_1_317"),  # 1862504124
        0x7A0D7F42: (
            message_action_group_call_struct,
            "message_action_group_call",
            None,
        ),  # 2047704898
        0x9FBAB604: (
            message_action_history_clear_struct,
            "message_action_history_clear",
            None,
        ),  # -1615153660
        0x555555F5: (
            message_action_login_unknown_location_struct,
            "message_action_login_unknown_location",
            None,
        ),  # 1431655925
        0x40699CD0: (
            message_action_payment_sent_struct,
            "message_action_payment_sent",
            None,
        ),  # 1080663248
        0x80E11A7F: (
            message_action_phone_call_struct,
            "message_action_phone_call",
            None,
        ),  # -2132731265
        0x94BD38ED: (
            message_action_pin_message_struct,
            "message_action_pin_message",
            None,
        ),  # -1799538451
        0x4792929B: (
            message_action_screenshot_taken_struct,
            "message_action_screenshot_taken",
            None,
        ),  # 1200788123
        0xD95C6154: (
            message_action_secure_values_sent_struct,
            "message_action_secure_values_sent",
            None,
        ),  # -648257196
        0x55555552: (
            message_action_ttl_change_struct,
            "message_action_ttl_change",
            None,
        ),  # 1431655762
        0x55555550: (
            message_action_user_joined_struct,
            "message_action_user_joined",
            None,
        ),  # 1431655760
        0x55555551: (
            message_action_user_updated_photo_struct,
            "message_action_user_updated_photo",
            None,
        ),  # 1431655761
        0x83E5DE54: (message_empty_struct, "message_empty", None),  # -2082087340
        0x555555F7: (
            message_encrypted_action_struct,
            "message_encrypted_action",
            None,
        ),  # 1431655927
        0x761E6AF4: (
            message_entity_bank_card_struct,
            "message_entity_bank_card",
            None,
        ),  # 1981704948
        0x020DF5D0: (
            message_entity_blockquote_struct,
            "message_entity_blockquote",
            None,
        ),  # 34469328
        0xBD610BC9: (
            message_entity_bold_struct,
            "message_entity_bold",
            None,
        ),  # -1117713463
        0x6CEF8AC7: (
            message_entity_bot_command_struct,
            "message_entity_bot_command",
            None,
        ),  # 1827637959
        0x4C4E743F: (
            message_entity_cashtag_struct,
            "message_entity_cashtag",
            None,
        ),  # 1280209983
        0x28A20571: (
            message_entity_code_struct,
            "message_entity_code",
            None,
        ),  # 681706865
        0x64E475C2: (
            message_entity_email_struct,
            "message_entity_email",
            None,
        ),  # 1692693954
        0x6F635B0D: (
            message_entity_hashtag_struct,
            "message_entity_hashtag",
            None,
        ),  # 1868782349
        0x826F8B60: (
            message_entity_italic_struct,
            "message_entity_italic",
            None,
        ),  # -2106619040
        0xFA04579D: (
            message_entity_mention_struct,
            "message_entity_mention",
            None,
        ),  # -100378723
        0x352DCA58: (
            message_entity_mention_name_struct,
            "message_entity_mention_name",
            None,
        ),  # 892193368
        0x9B69E34B: (
            message_entity_phone_struct,
            "message_entity_phone",
            None,
        ),  # -1687559349
        0x73924BE0: (
            message_entity_pre_struct,
            "message_entity_pre",
            None,
        ),  # 1938967520
        0xBF0693D4: (
            message_entity_strike_struct,
            "message_entity_strike",
            None,
        ),  # -1090087980
        0x76A6D327: (
            message_entity_text_url_struct,
            "message_entity_text_url",
            None,
        ),  # 1990644519
        0x9C4E7E8B: (
            message_entity_underline_struct,
            "message_entity_underline",
            None,
        ),  # -1672577397
        0xBB92BA95: (
            message_entity_unknown_struct,
            "message_entity_unknown",
            None,
        ),  # -1148011883
        0x6ED02538: (
            message_entity_url_struct,
            "message_entity_url",
            None,
        ),  # 1859134776
        0x05F46804: (
            message_forwarded_old_struct,
            "message_forwarded_old",
            None,
        ),  # 99903492
        0xA367E716: (
            message_forwarded_old2_struct,
            "message_forwarded_old2",
            None,
        ),  # -1553471722
        0x353A686B: (
            message_fwd_header_struct,
            "message_fwd_header",
            None,
        ),  # 893020267
        0xEC338270: (
            message_fwd_header_layer112_struct,
            "message_fwd_header_layer112",
            None,
        ),  # -332168592
        0xC786DDCB: (
            message_fwd_header_layer68_struct,
            "message_fwd_header_layer68",
            None,
        ),  # -947462709
        0xFADFF4AC: (
            message_fwd_header_layer72_struct,
            "message_fwd_header_layer72",
            None,
        ),  # -85986132
        0x559EBE6D: (
            message_fwd_header_layer96_struct,
            "message_fwd_header_layer96",
            None,
        ),  # 1436466797
        0xAD4FC9BD: (None, "message_interaction_counters", None),  # -1387279939
        0xC6B68300: (
            message_media_audio_layer45_struct,
            "message_media_audio_layer45",
            None,
        ),  # -961117440
        0xCBF24940: (
            message_media_contact_struct,
            "message_media_contact",
            None,
        ),  # -873313984
        0x5E7D2F39: (
            message_media_contact_layer81_struct,
            "message_media_contact_layer81",
            None,
        ),  # 1585262393
        0x3F7EE58B: (
            message_media_dice_struct,
            "message_media_dice",
            None,
        ),  # 1065280907
        0x638FE46B: (
            message_media_dice_layer111_struct,
            "message_media_dice_layer111",
            None,
        ),  # 1670374507
        0x9CB070D7: (
            message_media_document_struct,
            "message_media_document",
            None,
        ),  # -1666158377
        0xF3E02EA8: (
            message_media_document_layer68_struct,
            "message_media_document_layer68",
            None,
        ),  # -203411800
        0x7C4414D3: (
            message_media_document_layer74_struct,
            "message_media_document_layer74",
            None,
        ),  # 2084836563
        0x2FDA2204: (
            message_media_document_old_struct,
            "message_media_document_old",
            None,
        ),  # 802824708
        0x3DED6320: (
            message_media_empty_struct,
            "message_media_empty",
            None,
        ),  # 1038967584
        0xFDB19008: (
            message_media_game_struct,
            "message_media_game",
            None,
        ),  # -38694904
        0x56E0D474: (message_media_geo_struct, "message_media_geo", None),  # 1457575028
        0x7C3C2609: (
            message_media_geo_live_struct,
            "message_media_geo_live",
            None,
        ),  # 2084316681
        0x84551347: (
            message_media_invoice_struct,
            "message_media_invoice",
            None,
        ),  # -2074799289
        0x695150D7: (
            message_media_photo_struct,
            "message_media_photo",
            None,
        ),  # 1766936791
        0x3D8CE53D: (
            message_media_photo_layer68_struct,
            "message_media_photo_layer68",
            None,
        ),  # 1032643901
        0xB5223B0F: (
            message_media_photo_layer74_struct,
            "message_media_photo_layer74",
            None,
        ),  # -1256047857
        0xC8C45A2A: (
            message_media_photo_old_struct,
            "message_media_photo_old",
            None,
        ),  # -926655958
        0x4BD6E798: (
            message_media_poll_struct,
            "message_media_poll",
            None,
        ),  # 1272375192
        0x9F84F49E: (
            message_media_unsupported_struct,
            "message_media_unsupported",
            None,
        ),  # -1618676578
        0x29632A36: (
            message_media_unsupported_old_struct,
            "message_media_unsupported_old",
            None,
        ),  # 694364726
        0x2EC0533F: (
            message_media_venue_struct,
            "message_media_venue",
            None,
        ),  # 784356159
        0x7912B71F: (
            message_media_venue_layer71_struct,
            "message_media_venue_layer71",
            None,
        ),  # 2031269663
        0x5BCF1675: (
            message_media_video_layer45_struct,
            "message_media_video_layer45",
            None,
        ),  # 1540298357
        0xA2D24290: (
            message_media_video_old_struct,
            "message_media_video_old",
            None,
        ),  # -1563278704
        0xA32DD600: (
            message_media_web_page_struct,
            "message_media_web_page",
            None,
        ),  # -1557277184
        0x0AE30253: (None, "message_range", None),  # 182649427
        0xB87A24D1: (
            message_reactions_struct,
            "message_reactions",
            None,
        ),  # -1199954735
        0xE3AE6108: (None, "message_reactions_list", None),  # -475111160
        0x9E19A1F6: (message_service_struct, "message_service", None),  # -1642487306
        0xC06B9607: (
            message_service_layer48_struct,
            "message_service_layer48",
            None,
        ),  # -1066691065
        0x9F8D60BB: (
            message_service_old_struct,
            "message_service_old",
            None,
        ),  # -1618124613
        0x1D86F70E: (None, "message_service_old2", None),  # 495384334
        0xD267DCBC: (None, "message_user_reaction", None),  # -764945220
        0xA28E5559: (None, "message_user_vote", None),  # -1567730343
        0x36377430: (None, "message_user_vote_input_option", None),  # 909603888
        0x0E8FE0DE: (None, "message_user_vote_multiple", None),  # 244310238
        0x44F9B43D: (message_layer104_struct, "message_layer104", None),  # 1157215293
        0x1C9B1027: (
            message_layer104_2_struct,
            "message_layer104_2",
            None,
        ),  # 479924263
        0x9789DAC4: (
            message_layer104_3_struct,
            "message_layer104_3",
            None,
        ),  # -1752573244
        0xC992E15C: (None, "message_layer47", None),  # -913120932
        0xC09BE45F: (message_layer68_struct, "message_layer68", None),  # -1063525281
        0x90DDDC11: (message_layer72_struct, "message_layer72", None),  # -1864508399
        0x22EB6ABA: (None, "message_old", None),  # 585853626
        0x567699B3: (None, "message_old2", None),  # 1450613171
        0xA7AB1991: (message_old3_struct, "message_old3", None),  # -1481959023
        0xC3060325: (message_old4_struct, "message_old4", None),  # -1023016155
        0xF07814C8: (message_old5_struct, "message_old5", None),  # -260565816
        0x2BEBFA86: (None, "message_old6", None),  # 736885382
        0x5BA66C13: (None, "message_old7", None),  # 1537633299
        0x555555FA: (message_secret_struct, "message_secret", None),  # 1431655930
        0x555555F9: (None, "message_secret_layer72", None),  # 1431655929
        0x555555F8: (None, "message_secret_old", None),  # 1431655928
        0x3DBC0415: (None, "messages_accept_encryption", None),  # 1035731989
        0xF729EA98: (None, "messages_accept_url_auth", None),  # -148247912
        0xF9A0AA09: (None, "messages_add_chat_user", None),  # -106911223
        0x2EE9EE9E: (None, "messages_add_chat_user_v_0_1_317"),  # 787082910
        0xB45C69D1: (None, "messages_affected_history", None),  # -1269012015
        0xB7DE36F2: (None, "messages_affected_history_v_0_1_317"),  # -1210173710
        0x84D19185: (None, "messages_affected_messages", None),  # -2066640507
        0xEDFD405F: (None, "messages_all_stickers", None),  # -302170017
        0xE86602C3: (None, "messages_all_stickers_not_modified", None),  # -395967805
        0x4FCBA9C8: (None, "messages_archived_stickers", None),  # 1338747336
        0x36585EA4: (None, "messages_bot_callback_answer", None),  # 911761060
        0x947CA848: (None, "messages_bot_results", None),  # -1803769784
        0xCCD3563D: (None, "messages_bot_results_layer71", None),  # -858565059
        0x99262E37: (None, "messages_channel_messages", None),  # -1725551049
        0x40E9002A: (None, "messages_chat_v_0_1_317"),  # 1089011754
        0xE5D7D19C: (None, "messages_chat_full", None),  # -438840932
        0x64FF9FD5: (None, "messages_chats", None),  # 1694474197
        0x8150CBD8: (None, "messages_chats_v_0_1_317"),  # -2125411368
        0x9CD81144: (None, "messages_chats_slice", None),  # -1663561404
        0x3EADB1BB: (None, "messages_check_chat_invite", None),  # 1051570619
        0x7E58EE9C: (None, "messages_clear_all_drafts", None),  # 2119757468
        0x8999602D: (None, "messages_clear_recent_stickers", None),  # -1986437075
        0x09CB126E: (None, "messages_create_chat", None),  # 164303470
        0x419D9AEE: (None, "messages_create_chat_v_0_1_317"),  # 1100847854
        0xE0611F16: (None, "messages_delete_chat_user", None),  # -530505962
        0xC3C5CD23: (None, "messages_delete_chat_user_v_0_1_317"),  # -1010447069
        0x1C015B09: (None, "messages_delete_history", None),  # 469850889
        0xF4F8FB61: (None, "messages_delete_history_v_0_1_317"),  # -185009311
        0xE58E95D2: (None, "messages_delete_messages", None),  # -443640366
        0x59AE2B16: (None, "messages_delete_scheduled_messages", None),  # 1504586518
        0x14F2DD0A: (None, "messages_delete_messages_v_0_1_317"),  # 351460618
        0x2C221EDD: (None, "messages_dh_config", None),  # 740433629
        0xC0E24635: (None, "messages_dh_config_not_modified", None),  # -1058912715
        0x15BA6C40: (None, "messages_dialogs", None),  # 364538944
        0xF0E3E596: (None, "messages_dialogs_not_modified", None),  # -253500010
        0x71E094F3: (None, "messages_dialogs_slice", None),  # 1910543603
        0xEDD923C5: (None, "messages_discard_encryption", None),  # -304536635
        0xDEF60797: (None, "messages_edit_chat_about", None),  # -554301545
        0xA9E69F2E: (None, "messages_edit_chat_admin", None),  # -1444503762
        0xA5866B41: (
            None,
            "messages_edit_chat_default_banned_rights",
            None,
        ),  # -1517917375
        0xCA4C79D8: (None, "messages_edit_chat_photo", None),  # -900957736
        0xD881821D: (None, "messages_edit_chat_photo_v_0_1_317"),  # -662601187
        0xDC452855: (None, "messages_edit_chat_title", None),  # -599447467
        0xB4BC68B5: (None, "messages_edit_chat_title_v_0_1_317"),  # -1262720843
        0x48F71778: (None, "messages_edit_message", None),  # 1224152952
        0xD116F31E: (None, "messages_edit_message_v_5_6_2", None),  # -787025122
        0x0DF7534C: (None, "messages_export_chat_invite", None),  # 234312524
        0xB9FFC55B: (None, "messages_fave_sticker", None),  # -1174420133
        0xF37F2F16: (None, "messages_faved_stickers", None),  # -209768682
        0x9E8FA6D3: (None, "messages_faved_stickers_not_modified", None),  # -1634752813
        0xB6ABC341: (None, "messages_featured_stickers", None),  # -1230257343
        0xC6DC0C66: (
            None,
            "messages_featured_stickers_not_modified",
            None,
        ),  # -958657434
        0xF89D88E5: (None, "messages_featured_stickers_v_5_15_0", None),  # -123893531
        0x04EDE3CF: (
            None,
            "messages_featured_stickers_not_modified_v_5_15_0",
            None,
        ),  # 82699215
        0x33963BF9: (None, "messages_forward_message", None),  # 865483769
        0x03F3F4F2: (None, "messages_forward_message_v_0_1_317"),  # 66319602
        0xD9FEE60E: (None, "messages_forward_messages", None),  # -637606386
        0x514CD10F: (None, "messages_forward_messages_v_0_1_317"),  # 1363988751
        0x708E0195: (None, "messages_forward_messages_v_5_6_2", None),  # 1888354709
        0x450A1C0A: (None, "messages_found_gifs", None),  # 1158290442
        0x5108D648: (None, "messages_found_sticker_sets", None),  # 1359533640
        0x0D54B65D: (
            None,
            "messages_found_sticker_sets_not_modified",
            None,
        ),  # 223655517
        0xEBA80FF0: (None, "messages_get_all_chats", None),  # -341307408
        0x6A3F8D65: (None, "messages_get_all_drafts", None),  # 1782549861
        0x1C9618B1: (None, "messages_get_all_stickers", None),  # 479598769
        0x57F17692: (None, "messages_get_archived_stickers", None),  # 1475442322
        0xCC5B67CC: (None, "messages_get_attached_stickers", None),  # -866424884
        0x810A9FEC: (None, "messages_get_bot_callback_answer", None),  # -2130010132
        0x3C6AA187: (None, "messages_get_chats", None),  # 1013621127
        0x0D0A48C4: (None, "messages_get_common_chats", None),  # 218777796
        0x26CF8950: (None, "messages_get_dh_config", None),  # 651135312
        0xF19ED96D: (None, "messages_get_dialog_filters", None),  # -241247891
        0x22E24E22: (None, "messages_get_dialog_unread_marks", None),  # 585256482
        0xA0EE3B73: (None, "messages_get_dialogs", None),  # -1594999949
        0xB098AEE6: (None, "messages_get_dialogs_v_5_5_0", None),  # -1332171034
        0xECCF1DF6: (None, "messages_get_dialogs_v_0_1_317"),  # -321970698
        0x338E2464: (None, "messages_get_document_by_hash", None),  # 864953444
        0x35A0E062: (None, "messages_get_emoji_keywords", None),  # 899735650
        0x1508B6AF: (None, "messages_get_emoji_keywords_difference", None),  # 352892591
        0x4E9963B2: (None, "messages_get_emoji_keywords_languages", None),  # 1318675378
        0xD5B10C26: (None, "messages_get_emoji_url", None),  # -709817306
        0x21CE0B0E: (None, "messages_get_faved_stickers", None),  # 567151374
        0x2DACCA4F: (None, "messages_get_featured_stickers", None),  # 766298703
        0x3B831C66: (None, "messages_get_full_chat", None),  # 998448230
        0xE822649D: (None, "messages_get_game_high_scores", None),  # -400399203
        0xAFA92846: (None, "messages_get_history", None),  # -1347868602
        0x92A1DF2F: (None, "messages_get_history_v_0_1_317"),  # -1834885329
        0x514E999D: (None, "messages_get_inline_bot_results", None),  # 1364105629
        0x0F635E1B: (None, "messages_get_inline_game_high_scores", None),  # 258170395
        0x65B8C79F: (None, "messages_get_mask_stickers", None),  # 1706608543
        0xFDA68D36: (None, "messages_get_message_edit_data", None),  # -39416522
        0x15B1376A: (None, "messages_get_message_reactions_list", None),  # 363935594
        0x4222FA74: (None, "messages_get_messages", None),  # 1109588596
        0x8BBA90E6: (None, "messages_get_messages_reactions", None),  # -1950707482
        0xC4C8A55D: (None, "messages_get_messages_views", None),  # -993483427
        0x5FE7025B: (None, "messages_get_old_featured_stickers", None),  # 1608974939
        0x6E2BE050: (None, "messages_get_onlines", None),  # 1848369232
        0xE470BCFD: (None, "messages_get_peer_dialogs", None),  # -462373635
        0x3672E09C: (None, "messages_get_peer_settings", None),  # 913498268
        0xD6B94DF2: (None, "messages_get_pinned_dialogs", None),  # -692498958
        0xE254D64E: (None, "messages_get_pinned_dialogs_v_5_5_0", None),  # -497756594
        0x73BB643B: (None, "messages_get_poll_results", None),  # 1941660731
        0xB86E380E: (None, "messages_get_poll_votes", None),  # -1200736242
        0xBBC45B09: (None, "messages_get_recent_locations", None),  # -1144759543
        0x5EA192C9: (None, "messages_get_recent_stickers", None),  # 1587647177
        0x83BF3D52: (None, "messages_get_saved_gifs", None),  # -2084618926
        0xE2C2685B: (None, "messages_get_scheduled_history", None),  # -490575781
        0xBDBB0464: (None, "messages_get_scheduled_messages", None),  # -1111817116
        0x732EEF00: (None, "messages_get_search_counters", None),  # 1932455680
        0x812C2AE6: (None, "messages_get_stats_url", None),  # -2127811866
        0x2619A90E: (None, "messages_get_sticker_set", None),  # 639215886
        0x043D4F2C: (None, "messages_get_stickers", None),  # 71126828
        0xA29CD42C: (
            None,
            "messages_get_suggested_dialog_filters",
            None,
        ),  # -1566780372
        0x46578472: (None, "messages_get_unread_mentions", None),  # 1180140658
        0x32CA8F91: (None, "messages_get_web_page", None),  # 852135825
        0x8B68B0CC: (None, "messages_get_web_page_preview", None),  # -1956073268
        0x4FACB138: (None, "messages_hide_peer_settings_bar", None),  # 1336717624
        0xA8F1709B: (None, "messages_hide_report_spam_v_5_6_2", None),  # -1460572005
        0x9A3BFD99: (None, "messages_high_scores", None),  # -1707344487
        0x6C50051C: (None, "messages_import_chat_invite", None),  # 1817183516
        0xA927FEC5: (None, "messages_inactive_chats", None),  # -1456996667
        0xC78FE460: (None, "messages_install_sticker_set", None),  # -946871200
        0xC286D98F: (None, "messages_mark_dialog_unread", None),  # -1031349873
        0x26B5DDE6: (None, "messages_message_edit_data", None),  # 649453030
        0x3F4E0648: (None, "messages_message_empty", None),  # 1062078024
        0xFF90C417: (None, "messages_message_v_0_1_317"),  # -7289833
        0x8C718E87: (None, "messages_messages", None),  # -1938715001
        0x74535F21: (None, "messages_messages_not_modified", None),  # 1951620897
        0xC8EDCE1E: (None, "messages_messages_slice", None),  # -923939298
        0x0B446AE3: (None, "messages_messages_slice_v_0_1_317"),  # 189033187
        0xA6C47AAA: (None, "messages_messages_slice_v_5_6_2", None),  # -1497072982
        0x15A3B8E3: (None, "messages_migrate_chat", None),  # 363051235
        0x3371C354: (None, "messages_peer_dialogs", None),  # 863093588
        0x7F4B690A: (None, "messages_read_encrypted_history", None),  # 2135648522
        0x5B118126: (None, "messages_read_featured_stickers", None),  # 1527873830
        0x0E306D3A: (None, "messages_read_history", None),  # 238054714
        0xB04F2510: (None, "messages_read_history_v_0_1_317"),  # -1336990448
        0x0F0189D3: (None, "messages_read_mentions", None),  # 251759059
        0x36A73F77: (None, "messages_read_message_contents", None),  # 916930423
        0x05A954C0: (None, "messages_received_messages", None),  # 94983360
        0x28ABCB68: (None, "messages_received_messages_v_0_1_317"),  # 682347368
        0x55A5BB66: (None, "messages_received_queue", None),  # 1436924774
        0x22F3AFB3: (None, "messages_recent_stickers", None),  # 586395571
        0x0B17F890: (None, "messages_recent_stickers_not_modified", None),  # 186120336
        0x3B1ADF37: (None, "messages_reorder_pinned_dialogs", None),  # 991616823
        0x5B51D63F: (
            None,
            "messages_reorder_pinned_dialogs_v_5_5_0",
            None,
        ),  # 1532089919
        0x78337739: (None, "messages_reorder_sticker_sets", None),  # 2016638777
        0xBD82B658: (None, "messages_report", None),  # -1115507112
        0x4B0C8C0F: (None, "messages_report_encrypted_spam", None),  # 1259113487
        0xCF1592DB: (None, "messages_report_spam", None),  # -820669733
        0xF64DAF43: (None, "messages_request_encryption", None),  # -162681021
        0xE33F5613: (None, "messages_request_url_auth", None),  # -482388461
        0x395F9D7E: (None, "messages_restore_messages_v_0_1_317"),  # 962567550
        0xBC39E14B: (None, "messages_save_draft", None),  # -1137057461
        0x327A30CB: (None, "messages_save_gif", None),  # 846868683
        0x392718F8: (None, "messages_save_recent_sticker", None),  # 958863608
        0x2E0709A5: (None, "messages_saved_gifs", None),  # 772213157
        0xE8025CA2: (None, "messages_saved_gifs_not_modified", None),  # -402498398
        0x8614EF68: (None, "messages_search", None),  # -2045448344
        0xE844EBFF: (None, "messages_search_counter", None),  # -398136321
        0x07E9F2AB: (None, "messages_search_v_0_1_317"),  # 132772523
        0xBF9A776B: (None, "messages_search_gifs", None),  # -1080395925
        0xBF7225A4: (None, "messages_search_global", None),  # -1083038300
        0x9E3CACB0: (None, "messages_search_global_v_5_6_2", None),  # -1640190800
        0xC2B7D08B: (None, "messages_search_sticker_sets", None),  # -1028140917
        0xBF73F4DA: (None, "messages_send_broadcast_v_5_6_2", None),  # -1082919718
        0x41BB0972: (None, "messages_send_broadcast_v_0_1_317"),  # 1102776690
        0xA9776773: (None, "messages_send_encrypted", None),  # -1451792525
        0x9A901B66: (None, "messages_send_encrypted_file", None),  # -1701831834
        0xCACACACA: (None, "messages_send_encrypted_multi_media", None),  # -892679478
        0x32D439A4: (None, "messages_send_encrypted_service", None),  # 852769188
        0x220815B0: (None, "messages_send_inline_bot_result", None),  # 570955184
        0xB16E06FE: (
            None,
            "messages_send_inline_bot_result_v_5_6_2",
            None,
        ),  # -1318189314
        0x3491EBA9: (None, "messages_send_media", None),  # 881978281
        0xA3C85D76: (None, "messages_send_media_v_0_1_317"),  # -1547149962
        0xB8D1262B: (None, "messages_send_media_v_5_6_2", None),  # -1194252757
        0x520C3870: (None, "messages_send_message", None),  # 1376532592
        0x4CDE0AAB: (None, "messages_send_message_v_0_1_317"),  # 1289620139
        0xFA88427A: (None, "messages_send_message_v_5_6_2", None),  # -91733382
        0x2095512F: (None, "messages_send_multi_media_v_5_6_2", None),  # 546656559
        0x25690CE4: (None, "messages_send_reaction", None),  # 627641572
        0xBD38850A: (None, "messages_send_scheduled_messages", None),  # -1120369398
        0xC97DF020: (None, "messages_send_screenshot_notification", None),  # -914493408
        0x10EA6184: (None, "messages_send_vote", None),  # 283795844
        0xD1F4D35C: (None, "messages_sent_message_v_0_1_317"),  # -772484260
        0xE9DB4A3F: (None, "messages_sent_message_link_v_0_1_317"),  # -371504577
        0x9493FF32: (None, "messages_sent_encrypted_file", None),  # -1802240206
        0x560F8935: (None, "messages_sent_encrypted_message", None),  # 1443858741
        0xD58F130A: (None, "messages_set_bot_callback_answer", None),  # -712043766
        0x791451ED: (None, "messages_set_encrypted_typing", None),  # 2031374829
        0x8EF8ECC0: (None, "messages_set_game_score", None),  # -1896289088
        0x15AD9F64: (None, "messages_set_inline_game_score", None),  # 363700068
        0xA3825E50: (None, "messages_set_typing", None),  # -1551737264
        0x719839E9: (None, "messages_set_typing_v_0_1_317"),  # 1905801705
        0xE6DF7378: (None, "messages_start_bot", None),  # -421563528
        0xD07AE726: (None, "messages_stated_message_v_0_1_317"),  # -797251802
        0xA9AF2881: (None, "messages_stated_message_link_v_0_1_317"),  # -1448138623
        0x969478BB: (None, "messages_stated_messages_v_0_1_317"),  # -1768654661
        0x3E74F5C6: (None, "messages_stated_messages_links_v_0_1_317"),  # 1047852486
        0xB60A24A6: (None, "messages_sticker_set", None),  # -1240849242
        0x35E410A8: (
            None,
            "messages_sticker_set_install_result_archive",
            None,
        ),  # 904138920
        0x38641628: (
            None,
            "messages_sticker_set_install_result_success",
            None,
        ),  # 946083368
        0xE4599BBD: (None, "messages_stickers", None),  # -463889475
        0xF1749A22: (None, "messages_stickers_not_modified", None),  # -244016606
        0xA731E257: (None, "messages_toggle_dialog_pin", None),  # -1489903017
        0xB5052FEA: (None, "messages_toggle_sticker_sets", None),  # -1257951254
        0xF96E55DE: (None, "messages_uninstall_sticker_set", None),  # -110209570
        0x1AD4A04A: (None, "messages_update_dialog_filter", None),  # 450142282
        0xC563C1E4: (None, "messages_update_dialog_filters_order", None),  # -983318044
        0xD2AAF7EC: (None, "messages_update_pinned_message", None),  # -760547348
        0x5057C497: (None, "messages_upload_encrypted_file", None),  # 1347929239
        0x519BC2B1: (None, "messages_upload_media", None),  # 1369162417
        0x0823F649: (None, "messages_votes_list", None),  # 136574537
        0x73F1F8DC: (None, "msg_container_v_0_1_317"),  # 1945237724
        0xE06046B2: (None, "msg_copy_v_0_1_317"),  # -530561358
        0x276D3EC6: (None, "msg_detailed_info_v_0_1_317"),  # 661470918
        0x809DB6DF: (None, "msg_new_detailed_info_v_0_1_317"),  # -2137147681
        0x7D861A08: (None, "msg_resend_req_v_0_1_317"),  # 2105940488
        0x62D6B459: (None, "msgs_ack_v_0_1_317"),  # 1658238041
        0x8CC0D131: (None, "msgs_all_info_v_0_1_317"),  # -1933520591
        0x04DEB57D: (None, "msgs_state_info_v_0_1_317"),  # 81704317
        0xDA69FB52: (None, "msgs_state_req_v_0_1_317"),  # -630588590
        0x8E1A1775: (None, "nearest_dc", None),  # -1910892683
        0x9EC20908: (None, "new_session_created_v_0_1_317"),  # -1631450872
        0xD612E8EF: (None, "notify_broadcasts", None),  # -703403793
        0xC007CEC3: (None, "notify_chats", None),  # -1073230141
        0x9FD40BD8: (None, "notify_peer", None),  # -1613493288
        0xB4C83B4C: (None, "notify_users", None),  # -1261946036
        0x56730BCC: (None, "null", None),  # 1450380236
        0x83C95AEC: (None, "p_q_inner_data_v_0_1_317"),  # -2083955988
        0x98657F0D: (page_struct, "page", None),  # -1738178803
        0xCE0D37B0: (page_block_anchor_struct, "page_block_anchor", None),  # -837994576
        0x804361EA: (page_block_audio_struct, "page_block_audio", None),  # -2143067670
        0x31B81A7F: (
            page_block_audio_layer82_struct,
            "page_block_audio_layer82",
            None,
        ),  # 834148991
        0xBAAFE5E0: (
            page_block_author_date_struct,
            "page_block_author_date",
            None,
        ),  # -1162877472
        0x3D5B64F2: (
            page_block_author_date_layer60_struct,
            "page_block_author_date_layer60",
            None,
        ),  # 1029399794
        0x263D7C26: (
            page_block_blockquote_struct,
            "page_block_blockquote",
            None,
        ),  # 641563686
        0xEF1751B5: (
            page_block_channel_struct,
            "page_block_channel",
            None,
        ),  # -283684427
        0x65A0FA4D: (
            page_block_collage_struct,
            "page_block_collage",
            None,
        ),  # 1705048653
        0x08B31C4F: (
            page_block_collage_layer82_struct,
            "page_block_collage_layer82",
            None,
        ),  # 145955919
        0x39F23300: (page_block_cover_struct, "page_block_cover", None),  # 972174080
        0x76768BED: (
            page_block_details_struct,
            "page_block_details",
            None,
        ),  # 1987480557
        0xDB20B188: (
            page_block_divider_struct,
            "page_block_divider",
            None,
        ),  # -618614392
        0xA8718DC5: (page_block_embed_struct, "page_block_embed", None),  # -1468953147
        0xF259A80B: (
            page_block_embed_post_struct,
            "page_block_embed_post",
            None,
        ),  # -229005301
        0x292C7BE9: (
            page_block_embed_post_layer82_struct,
            "page_block_embed_post_layer82",
            None,
        ),  # 690781161
        0xD935D8FB: (
            page_block_embed_layer60_struct,
            "page_block_embed_layer60",
            None,
        ),  # -650782469
        0xCDE200D1: (
            page_block_embed_layer82_struct,
            "page_block_embed_layer82",
            None,
        ),  # -840826671
        0x48870999: (page_block_footer_struct, "page_block_footer", None),  # 1216809369
        0xBFD064EC: (
            page_block_header_struct,
            "page_block_header",
            None,
        ),  # -1076861716
        0x1E148390: (page_block_kicker_struct, "page_block_kicker", None),  # 504660880
        0xE4E88011: (page_block_list_struct, "page_block_list", None),  # -454524911
        0x3A58C7F4: (
            page_block_list_layer82_struct,
            "page_block_list_layer82",
            None,
        ),  # 978896884
        0xA44F3EF6: (page_block_map_struct, "page_block_map", None),  # -1538310410
        0x9A8AE1E1: (
            page_block_ordered_list_struct,
            "page_block_ordered_list",
            None,
        ),  # -1702174239
        0x467A0766: (
            page_block_paragraph_struct,
            "page_block_paragraph",
            None,
        ),  # 1182402406
        0x1759C560: (page_block_photo_struct, "page_block_photo", None),  # 391759200
        0xE9C69982: (
            page_block_photo_layer82_struct,
            "page_block_photo_layer82",
            None,
        ),  # -372860542
        0xC070D93E: (
            page_block_preformatted_struct,
            "page_block_preformatted",
            None,
        ),  # -1066346178
        0x4F4456D3: (
            page_block_pullquote_struct,
            "page_block_pullquote",
            None,
        ),  # 1329878739
        0x16115A96: (
            page_block_related_articles_struct,
            "page_block_related_articles",
            None,
        ),  # 370236054
        0x031F9590: (
            page_block_slideshow_struct,
            "page_block_slideshow",
            None,
        ),  # 52401552
        0x130C8963: (
            page_block_slideshow_layer82_struct,
            "page_block_slideshow_layer82",
            None,
        ),  # 319588707
        0xF12BB6E1: (
            page_block_subheader_struct,
            "page_block_subheader",
            None,
        ),  # -248793375
        0x8FFA9A1F: (
            page_block_subtitle_struct,
            "page_block_subtitle",
            None,
        ),  # -1879401953
        0xBF4DEA82: (page_block_table_struct, "page_block_table", None),  # -1085412734
        0x70ABC3FD: (page_block_title_struct, "page_block_title", None),  # 1890305021
        0x13567E8A: (
            page_block_unsupported_struct,
            "page_block_unsupported",
            None,
        ),  # 324435594
        0x7C8FE7B6: (page_block_video_struct, "page_block_video", None),  # 2089805750
        0xD9D71866: (
            page_block_video_layer82_struct,
            "page_block_video_layer82",
            None,
        ),  # -640214938
        0x6F747657: (page_caption_struct, "page_caption", None),  # 1869903447
        0xD7A19D69: (page_full_layer67_struct, "page_full_layer67", None),  # -677274263
        0x556EC7AA: (page_full_layer82_struct, "page_full_layer82", None),  # 1433323434
        0xAE891BEC: (page_layer110_struct, "page_layer110", None),  # -1366746132
        0x25E073FC: (
            page_list_item_blocks_struct,
            "page_list_item_blocks",
            None,
        ),  # 635466748
        0xB92FB6CD: (
            page_list_item_text_struct,
            "page_list_item_text",
            None,
        ),  # -1188055347
        0x98DD8936: (
            page_list_ordered_item_blocks_struct,
            "page_list_ordered_item_blocks",
            None,
        ),  # -1730311882
        0x5E068047: (
            page_list_ordered_item_text_struct,
            "page_list_ordered_item_text",
            None,
        ),  # 1577484359
        0x8DEE6C44: (
            page_part_layer67_struct,
            "page_part_layer67",
            None,
        ),  # -1913754556
        0x8E3F9EBE: (
            page_part_layer82_struct,
            "page_part_layer82",
            None,
        ),  # -1908433218
        0xB390DC08: (
            page_related_article_struct,
            "page_related_article",
            None,
        ),  # -1282352120
        0x34566B6A: (page_table_cell_struct, "page_table_cell", None),  # 878078826
        0xE0C0C5E5: (page_table_row_struct, "page_table_row", None),  # -524237339
        0x3A912D4A: (
            None,
            "password_kdf_algo_sha256_sha256_pbkdf2_hmac_sha512iter100000_sha256_mod_pow",
            None,
        ),  # 982592842
        0xD45AB096: (None, "password_kdf_algo_unknown", None),  # -732254058
        0x909C3F94: (None, "payment_requested_info", None),  # -1868808300
        0xCDC27A1F: (None, "payment_saved_credentials_card", None),  # -842892769
        0x3E24E573: (None, "payments_bank_card_data", None),  # 1042605427
        0xD83D70C1: (None, "payments_clear_saved_info", None),  # -667062079
        0x2E79D779: (None, "payments_get_bank_card_data", None),  # 779736953
        0x99F09745: (None, "payments_get_payment_form", None),  # -1712285883
        0xA092A980: (None, "payments_get_payment_receipt", None),  # -1601001088
        0x227D824B: (None, "payments_get_saved_info", None),  # 578650699
        0x3F56AEA3: (None, "payments_payment_form", None),  # 1062645411
        0x500911E1: (None, "payments_payment_receipt", None),  # 1342771681
        0x4E5F810D: (None, "payments_payment_result", None),  # 1314881805
        0xD8411139: (None, "payments_payment_verification_needed", None),  # -666824391
        0x6B56B921: (
            None,
            "payments_payment_verfication_needed_v_5_6_2",
            None,
        ),  # 1800845601
        0xFB8FE43C: (None, "payments_saved_info", None),  # -74456004
        0x2B8879B3: (None, "payments_send_payment_form", None),  # 730364339
        0x770A8E74: (None, "payments_validate_requested_info", None),  # 1997180532
        0xD1451883: (None, "payments_validated_requested_info", None),  # -784000893
        0xBDDDE532: (peer_channel_struct, "peer_channel", None),  # -1109531342
        0xBAD0E5BB: (peer_chat_struct, "peer_chat", None),  # -1160714821
        0xCA461B5D: (None, "peer_located", None),  # -901375139
        0x6D1DED88: (None, "peer_notify_events_all_v_0_1_317"),  # 1830677896
        0xADD53CB3: (None, "peer_notify_events_empty_v_0_1_317"),  # -1378534221
        0xAF509D20: (
            peer_notify_settings_struct,
            "peer_notify_settings",
            None,
        ),  # -1353671392
        0x70A68512: (
            peer_notify_settings_empty_layer77_struct,
            "peer_notify_settings_empty_layer77",
            None,
        ),  # 1889961234
        0x8D5E11EE: (
            peer_notify_settings_layer47_struct,
            "peer_notify_settings_layer47",
            None,
        ),  # -1923214866
        0x9ACDA4C0: (
            peer_notify_settings_layer77_struct,
            "peer_notify_settings_layer77",
            None,
        ),  # -1697798976
        0xF8EC284B: (None, "peer_self_located", None),  # -118740917
        0x733F2961: (peer_settings_struct, "peer_settings", None),  # 1933519201
        0x818426CD: (
            peer_settings_v_5_15_0_struct,
            "peer_settings_v_5_15_0",
            None,
        ),  # -2122045747
        0x9DB1BC6D: (peer_user_struct, "peer_user", None),  # -1649296275
        0x8742AE7F: (None, "phone_call", None),  # -2025673089
        0xE6F9DDF3: (None, "phone_call_v_5_5_0", None),  # -419832333
        0x997C454A: (None, "phone_call_accepted", None),  # -1719909046
        0x6D003D3F: (None, "phone_call_accepted_v_5_5_0", None),  # 1828732223
        0xAFE2B839: (
            phone_call_discard_reason_allow_group_call_struct,
            "phone_call_discard_reason_allow_group_call",
            None,
        ),  # -1344096199
        0xFAF7E8C9: (
            phone_call_discard_reason_busy_struct,
            "phone_call_discard_reason_busy",
            None,
        ),  # -84416311
        0xE095C1A0: (
            phone_call_discard_reason_disconnect_struct,
            "phone_call_discard_reason_disconnect",
            None,
        ),  # -527056480
        0x57ADC690: (
            phone_call_discard_reason_hangup_struct,
            "phone_call_discard_reason_hangup",
            None,
        ),  # 1471006352
        0x85E42301: (
            phone_call_discard_reason_missed_struct,
            "phone_call_discard_reason_missed",
            None,
        ),  # -2048646399
        0x50CA4DE1: (
            phone_call_discarded_struct,
            "phone_call_discarded",
            None,
        ),  # 1355435489
        0x5366C915: (None, "phone_call_empty", None),  # 1399245077
        0xFC878FC8: (None, "phone_call_protocol", None),  # -58224696
        0xA2BB35CB: (None, "phone_call_protocol_layer110", None),  # -1564789301
        0x87EABB53: (None, "phone_call_requested", None),  # -2014659757
        0x83761CE4: (None, "phone_call_requested_v_5_5_0", None),  # -2089411356
        0x1B8F4AD1: (None, "phone_call_waiting", None),  # 462375633
        0xFFE6AB67: (None, "phone_call_layer86_v_5_5_0", None),  # -1660057
        0x9D4C17C0: (None, "phone_connection", None),  # -1655957568
        0x3BD2B4A0: (None, "phone_accept_call", None),  # 1003664544
        0x2EFE1722: (None, "phone_confirm_call", None),  # 788404002
        0x8504E5B6: (None, "phone_create_group_call", None),  # -2063276618
        0xB2CBC1C0: (None, "phone_discard_call", None),  # -1295269440
        0x78D413A6: (None, "phone_discard_call_v_5_5_0", None),  # 2027164582
        0x7A777135: (None, "phone_discard_group_call", None),  # 2054648117
        0x46659BE4: (None, "phone_edit_group_call_member", None),  # 1181064164
        0x8ADB4F79: (None, "phone_get_call", None),  # -1965338759
        0x55451FA9: (None, "phone_get_call_config", None),  # 1430593449
        0x0C7CB017: (None, "phone_get_group_call", None),  # 209498135
        0x6737FFB7: (None, "phone_group_call", None),  # 1731723191
        0xCC92A6DC: (None, "phone_invite_group_call_members", None),  # -862804260
        0x09DB32D7: (None, "phone_join_group_call", None),  # 165360343
        0x60E98E5F: (None, "phone_leave_group_call", None),  # 1625919071
        0xEC82E140: (None, "phone_phone_call", None),  # -326966976
        0x17D54F61: (None, "phone_received_call", None),  # 399855457
        0x42FF96ED: (None, "phone_request_call", None),  # 1124046573
        0x5B95B3D4: (None, "phone_request_call_v_5_5_0", None),  # 1536537556
        0x277ADD7E: (None, "phone_save_call_debug", None),  # 662363518
        0x59EAD627: (None, "phone_set_call_rating", None),  # 1508562471
        0x1C536A34: (None, "phone_set_call_rating_v_5_5_0", None),  # 475228724
        0x98E3CDBA: (None, "phone_upgrade_phone_call", None),  # -1729901126
        0xFB197A65: (photo_struct, "photo", None),  # -82216347
        0xE9A734FA: (photo_cached_size_struct, "photo_cached_size", None),  # -374917894
        0x2331B22D: (photo_empty_struct, "photo_empty", None),  # 590459437
        0xD07504A5: (photo_layer115_struct, "photo_layer115", None),  # -797637467
        0x77BFB61B: (photo_size_struct, "photo_size", None),  # 2009052699
        0x0E17E23C: (photo_size_empty_struct, "photo_size_empty", None),  # 236446268
        0xCDED42FE: (photo_layer55_struct, "photo_layer55", None),  # -840088834
        0x9288DD29: (photo_layer82_struct, "photo_layer82", None),  # -1836524247
        0x9C477DD8: (photo_layer97_struct, "photo_layer97", None),  # -1673036328
        0x22B56751: (photo_old_struct, "photo_old", None),  # 582313809
        0xC3838076: (photo_old2_struct, "photo_old2", None),  # -1014792074
        0xE0B0BC2E: (
            photo_stripped_size_struct,
            "photo_stripped_size",
            None,
        ),  # -525288402
        0x87CF7F2F: (None, "photos_delete_photos", None),  # -2016444625
        0x91CD32A8: (None, "photos_get_user_photos", None),  # -1848823128
        0xB7EE553C: (None, "photos_get_user_photos_v_0_1_317"),  # -1209117380
        0x20212CA8: (None, "photos_photo", None),  # 539045032
        0x8DCA6AA5: (None, "photos_photos", None),  # -1916114267
        0x15051F54: (None, "photos_photos_slice", None),  # 352657236
        0x72D4742C: (None, "photos_update_profile_photo", None),  # 1926525996
        0xEEF579A0: (None, "photos_update_profile_photo_v_0_1_317"),  # -285902432
        0xF0BB5152: (None, "photos_update_profile_photo_v_5_15_0", None),  # -256159406
        0x89F30F69: (None, "photos_upload_profile_photo", None),  # -1980559511
        0xD50F9C88: (None, "photos_upload_profile_photo_v_0_1_317"),  # -720397176
        0x4F32C098: (None, "photos_upload_profile_photo_v_5_15_0", None),  # 1328726168
        0x7ABE77EC: (None, "ping_v_0_1_317"),  # 2059302892
        0x86E18161: (poll_struct, "poll", None),  # -2032041631
        0x6CA9C2E9: (poll_answer_struct, "poll_answer", None),  # 1823064809
        0x3B6DDAD2: (
            poll_answer_voters_struct,
            "poll_answer_voters",
            None,
        ),  # 997055186
        0xD5529D06: (poll_layer111_struct, "poll_layer111", None),  # -716006138
        0xBADCC1A3: (poll_results_struct, "poll_results", None),  # -1159937629
        0x5755785A: (
            poll_results_layer108_struct,
            "poll_results_layer108",
            None,
        ),  # 1465219162
        0xC87024A2: (
            poll_results_layer111_struct,
            "poll_results_layer111",
            None,
        ),  # -932174686
        0xAF746786: (poll_to_delete_struct, "poll_to_delete", None),  # -1351325818
        0x347773C5: (None, "pong_v_0_1_317"),  # 880243653
        0x5CE14175: (None, "popular_contact", None),  # 1558266229
        0x1E8CAAEB: (None, "post_address", None),  # 512535275
        0x42FFD42B: (None, "privacy_key_added_by_phone", None),  # 1124062251
        0x500E6DFA: (None, "privacy_key_chat_invite", None),  # 1343122938
        0x69EC56A3: (None, "privacy_key_forwards", None),  # 1777096355
        0x3D662B7B: (None, "privacy_key_phone_call", None),  # 1030105979
        0xD19AE46D: (None, "privacy_key_phone_number", None),  # -778378131
        0x39491CC8: (None, "privacy_key_phone_p2p", None),  # 961092808
        0x96151FED: (None, "privacy_key_profile_photo", None),  # -1777000467
        0xBC2EAB30: (None, "privacy_key_status_timestamp", None),  # -1137792208
        0x65427B82: (None, "privacy_value_allow_all", None),  # 1698855810
        0x18BE796B: (None, "privacy_value_allow_chat_participants", None),  # 415136107
        0xFFFE1BAC: (None, "privacy_value_allow_contacts", None),  # -123988
        0x4D5BBE0C: (None, "privacy_value_allow_users", None),  # 1297858060
        0x8B73E763: (None, "privacy_value_disallow_all", None),  # -1955338397
        0xACAE0690: (
            None,
            "privacy_value_disallow_chat_participants",
            None,
        ),  # -1397881200
        0xF888FA1A: (None, "privacy_value_disallow_contacts", None),  # -125240806
        0x0C7F49B7: (None, "privacy_value_disallow_users", None),  # 209668535
        0x5BB8E511: (None, "proto_message_v_0_1_317"),  # 1538843921
        0x6FB250D1: (reaction_count_struct, "reaction_count", None),  # 1873957073
        0xA384B779: (None, "received_notify_message", None),  # -1551583367
        0xA01B22F9: (None, "recent_me_url_chat", None),  # -1608834311
        0xEB49081D: (None, "recent_me_url_chat_invite", None),  # -347535331
        0xBC0A57DC: (None, "recent_me_url_sticker_set", None),  # -1140172836
        0x46E1D13D: (None, "recent_me_url_unknown", None),  # 1189204285
        0x8DBC3336: (None, "recent_me_url_user", None),  # -1917045962
        0x48A30254: (
            reply_inline_markup_struct,
            "reply_inline_markup",
            None,
        ),  # 1218642516
        0xF4108AA0: (
            reply_keyboard_force_reply_struct,
            "reply_keyboard_force_reply",
            None,
        ),  # -200242528
        0xA03E5B85: (
            reply_keyboard_hide_struct,
            "reply_keyboard_hide",
            None,
        ),  # -1606526075
        0x3502758C: (
            reply_keyboard_markup_struct,
            "reply_keyboard_markup",
            None,
        ),  # 889353612
        0xD712E4BE: (None, "req_dh_params_v_0_1_317"),  # -686627650
        0x60469778: (None, "req_pq_v_0_1_317"),  # 1615239032
        0x05162463: (None, "res_pq_v_0_1_317"),  # 85337187
        0xD072ACB4: (
            restriction_reason_struct,
            "restriction_reason",
            None,
        ),  # -797791052
        0xA43AD8B7: (None, "rpc_answer_dropped_v_0_1_317"),  # -1539647305
        0xCD78E586: (None, "rpc_answer_dropped_running_v_0_1_317"),  # -847714938
        0x5E2AD36E: (None, "rpc_answer_unknown_v_0_1_317"),  # 1579864942
        0x58E4A740: (None, "rpc_drop_answer_v_0_1_317"),  # 1491380032
        0x2144CA19: (None, "rpc_error_v_0_1_317"),  # 558156313
        0x7AE432F5: (None, "rpc_req_error_v_0_1_317"),  # 2061775605
        0xF35C6D01: (None, "rpc_result_v_0_1_317"),  # -212046591
        0x33F0EA47: (None, "secure_credentials_encrypted", None),  # 871426631
        0x8AEABEC3: (None, "secure_data", None),  # -1964327229
        0xE0277A62: (None, "secure_file", None),  # -534283678
        0x64199744: (None, "secure_file_empty", None),  # 1679398724
        0xBBF2DDA0: (
            None,
            "secure_password_kdf_algo_pbkdf2_hmac_sha512_iter100000",
            None,
        ),  # -1141711456
        0x86471D92: (None, "secure_password_kdf_algo_sha512", None),  # -2042159726
        0x004A8537: (None, "secure_password_kdf_algo_unknown", None),  # 4883767
        0x21EC5A5F: (None, "secure_plain_email", None),  # 569137759
        0x7D6099DD: (None, "secure_plain_phone", None),  # 2103482845
        0x829D99DA: (None, "secure_required_type", None),  # -2103600678
        0x027477B4: (None, "secure_required_type_one_of", None),  # 41187252
        0x1527BCAC: (None, "secure_secret_settings", None),  # 354925740
        0x187FA0CA: (None, "secure_value", None),  # 411017418
        0x869D758F: (None, "secure_value_error", None),  # -2036501105
        0xE8A40BD9: (None, "secure_value_error_data", None),  # -391902247
        0x7A700873: (None, "secure_value_error_file", None),  # 2054162547
        0x666220E9: (None, "secure_value_error_files", None),  # 1717706985
        0x00BE3DFA: (None, "secure_value_error_front_side", None),  # 12467706
        0x868A2AA5: (None, "secure_value_error_reverse_side", None),  # -2037765467
        0xE537CED6: (None, "secure_value_error_selfie", None),  # -449327402
        0xA1144770: (None, "secure_value_error_translation_file", None),  # -1592506512
        0x34636DD8: (None, "secure_value_error_translation_files", None),  # 878931416
        0xED1ECDB0: (None, "secure_value_hash", None),  # -316748368
        0xCBE31E26: (
            secure_value_type_address_struct,
            "secure_value_type_address",
            None,
        ),  # -874308058
        0x89137C0D: (
            secure_value_type_bank_statement_struct,
            "secure_value_type_bank_statement",
            None,
        ),  # -1995211763
        0x06E425C4: (
            secure_value_type_driver_license_struct,
            "secure_value_type_driver_license",
            None,
        ),  # 115615172
        0x8E3CA7EE: (
            secure_value_type_email_struct,
            "secure_value_type_email",
            None,
        ),  # -1908627474
        0xA0D0744B: (
            secure_value_type_identity_card_struct,
            "secure_value_type_identity_card",
            None,
        ),  # -1596951477
        0x99A48F23: (
            secure_value_type_internal_passport_struct,
            "secure_value_type_internal_passport",
            None,
        ),  # -1717268701
        0x3DAC6A00: (
            secure_value_type_passport_struct,
            "secure_value_type_passport",
            None,
        ),  # 1034709504
        0x99E3806A: (
            secure_value_type_passport_registration_struct,
            "secure_value_type_passport_registration",
            None,
        ),  # -1713143702
        0x9D2A81E3: (
            secure_value_type_personal_details_struct,
            "secure_value_type_personal_details",
            None,
        ),  # -1658158621
        0xB320AADB: (
            secure_value_type_phone_struct,
            "secure_value_type_phone",
            None,
        ),  # -1289704741
        0x8B883488: (
            secure_value_type_rental_agreement_struct,
            "secure_value_type_rental_agreement",
            None,
        ),  # -1954007928
        0xEA02EC33: (
            secure_value_type_temporary_registration_struct,
            "secure_value_type_temporary_registration",
            None,
        ),  # -368907213
        0xFC36954E: (
            secure_value_type_utility_bill_struct,
            "secure_value_type_utility_bill",
            None,
        ),  # -63531698
        0xFD5EC8F5: (
            send_message_cancel_action_struct,
            "send_message_cancel_action",
            None,
        ),  # -44119819
        0x628CBC6F: (
            send_message_choose_contact_action_struct,
            "send_message_choose_contact_action",
            None,
        ),  # 1653390447
        0xDD6A8F48: (
            send_message_game_play_action_struct,
            "send_message_game_play_action",
            None,
        ),  # -580219064
        0x176F8BA1: (
            send_message_geo_location_action_struct,
            "send_message_geo_location_action",
            None,
        ),  # 393186209
        0xD52F73F7: (
            send_message_record_audio_action_struct,
            "send_message_record_audio_action",
            None,
        ),  # -718310409
        0x88F27FBC: (
            send_message_record_round_action_struct,
            "send_message_record_round_action",
            None,
        ),  # -1997373508
        0xA187D66F: (
            send_message_record_video_action_struct,
            "send_message_record_video_action",
            None,
        ),  # -1584933265
        0x16BF744E: (
            send_message_typing_action_struct,
            "send_message_typing_action",
            None,
        ),  # 381645902
        0xF351D7AB: (
            send_message_upload_audio_action_struct,
            "send_message_upload_audio_action",
            None,
        ),  # -212740181
        0xE6AC8A6F: (
            send_message_upload_audio_action_old_struct,
            "send_message_upload_audio_action_old",
            None,
        ),  # -424899985
        0xAA0CD9E4: (
            send_message_upload_document_action_struct,
            "send_message_upload_document_action",
            None,
        ),  # -1441998364
        0x8FAEE98E: (
            send_message_upload_document_action_old_struct,
            "send_message_upload_document_action_old",
            None,
        ),  # -1884362354
        0xD1D34A26: (
            send_message_upload_photo_action_struct,
            "send_message_upload_photo_action",
            None,
        ),  # -774682074
        0x990A3C1A: (
            send_message_upload_photo_action_old_struct,
            "send_message_upload_photo_action_old",
            None,
        ),  # -1727382502
        0x243E1C66: (
            send_message_upload_round_action_struct,
            "send_message_upload_round_action",
            None,
        ),  # 608050278
        0xE9763AEC: (
            send_message_upload_video_action_struct,
            "send_message_upload_video_action",
            None,
        ),  # -378127636
        0x92042FF7: (
            send_message_upload_video_action_old_struct,
            "send_message_upload_video_action_old",
            None,
        ),  # -1845219337
        0xB5890DBA: (None, "server_dh_inner_data_v_0_1_317"),  # -1249309254
        0x79CB045D: (None, "server_dh_params_fail_v_0_1_317"),  # 2043348061
        0xD0E8075C: (None, "server_dh_params_ok_v_0_1_317"),  # -790100132
        0xF5045F1F: (None, "set_client_dh_params_v_0_1_317"),  # -184262881
        0xB6213CDF: (None, "shipping_option", None),  # -1239335713
        0xCB43ACDE: (None, "stats_abs_value_and_prev", None),  # -884757282
        0xBDF78394: (None, "stats_broadcast_stats", None),  # -1107852396
        0xB637EDAF: (None, "stats_date_range_days", None),  # -1237848657
        0xAB42441A: (None, "stats_get_broadcast_stats", None),  # -1421720550
        0xDCDF8607: (None, "stats_get_megagroup_stats", None),  # -589330937
        0x4A27EB2D: (None, "stats_graph_async", None),  # 1244130093
        0xBEDC9822: (None, "stats_graph_error", None),  # -1092839390
        0x8EA464B6: (None, "stats_graph", None),  # -1901828938
        0x6014F412: (None, "stats_group_top_admin", None),  # 1611985938
        0x31962A4C: (None, "stats_group_top_inviter", None),  # 831924812
        0x18F3D0F7: (None, "stats_group_top_poster", None),  # 418631927
        0x621D5FA0: (None, "stats_load_async_graph", None),  # 1646092192
        0xEF7FF916: (None, "stats_megagroup_stats", None),  # -276825834
        0xCBCE2FE0: (None, "stats_percent_value", None),  # -875679776
        0x47A971E0: (None, "stats_url", None),  # 1202287072
        0x12B299D4: (None, "sticker_pack", None),  # 313694676
        0xEEB46F27: (None, "sticker_set", None),  # -290164953
        0x6410A5D2: (None, "sticker_set_covered", None),  # 1678812626
        0x3407E51B: (None, "sticker_set_multi_covered", None),  # 872932635
        0xCD303B41: (None, "sticker_set_layer75", None),  # -852477119
        0x5585A139: (None, "sticker_set_layer96", None),  # 1434820921
        0x6A90BCB7: (None, "sticker_set_layer97", None),  # 1787870391
        0xA7A43B17: (None, "sticker_set_old", None),  # -1482409193
        0xCAE1AADF: (None, "storage_file_gif", None),  # -891180321
        0x007EFE0E: (None, "storage_file_jpeg", None),  # 8322574
        0x4B09EBBC: (None, "storage_file_mov", None),  # 1258941372
        0x528A0677: (None, "storage_file_mp3", None),  # 1384777335
        0xB3CEA0E4: (None, "storage_file_mp4", None),  # -1278304028
        0x40BC6F52: (None, "storage_file_partial", None),  # 1086091090
        0xAE1E508D: (None, "storage_file_pdf", None),  # -1373745011
        0x0A4F63C0: (None, "storage_file_png", None),  # 172975040
        0xAA963B05: (None, "storage_file_unknown", None),  # -1432995067
        0x1081464C: (None, "storage_file_webp", None),  # 276907596
        0x35553762: (text_anchor_struct, "text_anchor", None),  # 894777186
        0x6724ABC4: (text_bold_struct, "text_bold", None),  # 1730456516
        0x7E6260D7: (text_concat_struct, "text_concat", None),  # 2120376535
        0xDE5A0DD6: (text_email_struct, "text_email", None),  # -564523562
        0xDC3D824F: (text_empty_struct, "text_empty", None),  # -599948721
        0x6C3F19B9: (text_fixed_struct, "text_fixed", None),  # 1816074681
        0x081CCF4F: (text_image_struct, "text_image", None),  # 136105807
        0xD912A59C: (text_italic_struct, "text_italic", None),  # -653089380
        0x034B8621: (text_marked_struct, "text_marked", None),  # 55281185
        0x1CCB966A: (text_phone_struct, "text_phone", None),  # 483104362
        0x744694E0: (text_plain_struct, "text_plain", None),  # 1950782688
        0x9BF8BB95: (text_strike_struct, "text_strike", None),  # -1678197867
        0xED6A8504: (text_subscript_struct, "text_subscript", None),  # -311786236
        0xC7FB5E01: (text_superscript_struct, "text_superscript", None),  # -939827711
        0xC12622C4: (text_underline_struct, "text_underline", None),  # -1054465340
        0x3C2884C1: (text_url_struct, "text_url", None),  # 1009288385
        0x028F1114: (None, "theme", None),  # 42930452
        0x483D270C: (None, "theme_document_not_modified_layer106", None),  # 1211967244
        0x9C14984A: (theme_settings_struct, "theme_settings", None),  # -1676371894
        0xF7D90CE0: (None, "theme_layer106", None),  # -136770336
        0xEDCDC05B: (None, "top_peer", None),  # -305282981
        0x148677E2: (None, "top_peer_category_bots_inline", None),  # 344356834
        0xAB661B5B: (None, "top_peer_category_bots_p_m", None),  # -1419371685
        0x161D9628: (None, "top_peer_category_channels", None),  # 371037736
        0x0637B7ED: (None, "top_peer_category_correspondents", None),  # 104314861
        0xFBEEC0F0: (None, "top_peer_category_forward_chats", None),  # -68239120
        0xA8406CA9: (None, "top_peer_category_forward_users", None),  # -1472172887
        0xBD17A14A: (None, "top_peer_category_groups", None),  # -1122524854
        0xFB834291: (None, "top_peer_category_peers", None),  # -75283823
        0x1E76A78C: (None, "top_peer_category_phone_calls", None),  # 511092620
        0x6F690963: (None, "update_activation_v_0_1_317"),  # 1869154659
        0xB6D45656: (None, "update_channel", None),  # -1227598250
        0x70DB6837: (None, "update_channel_available_messages", None),  # 1893427255
        0x98A12B4B: (None, "update_channel_message_views", None),  # -1734268085
        0x65D2B464: (None, "update_channel_participant", None),  # 1708307556
        0x98592475: (None, "update_channel_pinned_message", None),  # -1738988427
        0x89893B45: (
            None,
            "update_channel_read_messages_contents",
            None,
        ),  # -1987495099
        0xEB0467FB: (None, "update_channel_too_long", None),  # -352032773
        0x40771900: (None, "update_channel_web_page", None),  # 1081547008
        0x54C01850: (None, "update_chat_default_banned_rights", None),  # 1421875280
        0xEA4B0E5C: (None, "update_chat_participant_add", None),  # -364179876
        0x3A0EEB22: (None, "update_chat_participant_add_v_0_1_317"),  # 974056226
        0xB6901959: (None, "update_chat_participant_admin", None),  # -1232070311
        0x6E5F8C22: (None, "update_chat_participant_delete", None),  # 1851755554
        0x07761198: (None, "update_chat_participants", None),  # 125178264
        0xE10DB349: (None, "update_chat_pinned_message", None),  # -519195831
        0x9A65EA1F: (None, "update_chat_user_typing", None),  # -1704596961
        0x3C46CFE6: (None, "update_chat_user_typing_v_0_1_317"),  # 1011273702
        0xA229DD06: (None, "update_config", None),  # -1574314746
        0x9D2E67C5: (None, "update_contact_link", None),  # -1657903163
        0x51A48A9A: (None, "update_contact_link_v_0_1_317"),  # 1369737882
        0x2575BBB9: (None, "update_contact_registered_v_0_1_317"),  # 628472761
        0x7084A7BE: (None, "update_contacts_reset", None),  # 1887741886
        0x8E5E9873: (None, "update_dc_options", None),  # -1906403213
        0xC37521C9: (None, "update_delete_channel_messages", None),  # -1015733815
        0xA20DB0E5: (None, "update_delete_messages", None),  # -1576161051
        0xA92BFE26: (None, "update_delete_messages_v_0_1_317"),  # -1456734682
        0x90866CEE: (None, "update_delete_scheduled_messages", None),  # -1870238482
        0x26FFDE7D: (None, "update_dialog_filter", None),  # 654302845
        0xA5D72105: (None, "update_dialog_filter_order", None),  # -1512627963
        0x3504914F: (None, "update_dialog_filters", None),  # 889491791
        0x6E6FE51C: (None, "update_dialog_pinned", None),  # 1852826908
        0x19D27F3C: (None, "update_dialog_pinned_v_5_5_0", None),  # 433225532
        0xE16459C3: (None, "update_dialog_unread_mark", None),  # -513517117
        0xEE2BB969: (None, "update_draft_message", None),  # -299124375
        0x1B3F4DF7: (None, "update_edit_channel_message", None),  # 457133559
        0xE40370A3: (None, "update_edit_message", None),  # -469536605
        0x1710F156: (None, "update_encrypted_chat_typing", None),  # 386986326
        0x38FE25B7: (None, "update_encrypted_messages_read", None),  # 956179895
        0xB4A2E88D: (None, "update_encryption", None),  # -1264392051
        0xE511996D: (None, "update_faved_stickers", None),  # -451831443
        0x19360DC0: (None, "update_folder_peers", None),  # 422972864
        0x871FB939: (None, "update_geo_live_viewed", None),  # -2027964103
        0x85FE86ED: (None, "update_group_call", None),  # -2046916883
        0x057EAEC8: (None, "update_group_call_participant", None),  # 92188360
        0x56022F4D: (None, "update_lang_pack", None),  # 1442983757
        0x46560264: (None, "update_lang_pack_too_long", None),  # 1180041828
        0x564FE691: (None, "update_login_token", None),  # 1448076945
        0x4E90BFD6: (None, "update_message_i_d", None),  # 1318109142
        0xACA1657B: (None, "update_message_poll", None),  # -1398708869
        0x154798C3: (None, "update_message_reactions", None),  # 357013699
        0x8F06529A: (None, "update_new_authorization_v_0_1_317"),  # -1895411046
        0x62BA04D9: (None, "update_new_channel_message", None),  # 1656358105
        0x12BCBD9A: (None, "update_new_encrypted_message", None),  # 314359194
        0x5A68E3F7: (None, "update_new_geo_chat_message_v_0_1_317"),  # 1516823543
        0x1F2B0AFD: (None, "update_new_message", None),  # 522914557
        0x013ABDB3: (None, "update_new_message_v_0_1_317"),  # 20626867
        0x39A51DFB: (None, "update_new_scheduled_message", None),  # 967122427
        0x688A30AA: (None, "update_new_sticker_set", None),  # 1753886890
        0xBEC268EF: (None, "update_notify_settings", None),  # -1094555409
        0xB4AFCFB0: (None, "update_peer_located", None),  # -1263546448
        0x6A7E7366: (None, "update_peer_settings", None),  # 1786671974
        0xAB0F6B1E: (None, "update_phone_call", None),  # -1425052898
        0x2661BF09: (None, "update_phone_call_signaling_data", None),  # 643940105
        0xFA0F3CA2: (None, "update_pinned_dialogs", None),  # -99664734
        0xEA4CB65B: (None, "update_pinned_dialogs_v_5_5_0", None),  # -364071333
        0xEE3B272A: (None, "update_privacy", None),  # -298113238
        0x330B5424: (None, "update_read_channel_inbox", None),  # 856380452
        0x4214F37F: (None, "update_read_channel_inbox_v_5_5_0", None),  # 1108669311
        0x25D6C9C7: (None, "update_read_channel_outbox", None),  # 634833351
        0x571D2742: (None, "update_read_featured_stickers", None),  # 1461528386
        0x9C974FDF: (None, "update_read_history_inbox", None),  # -1667805217
        0x9961FD5C: (None, "update_read_history_inbox_v_5_5_0", None),  # -1721631396
        0x2F2F21BF: (None, "update_read_history_outbox", None),  # 791617983
        0x68C13933: (None, "update_read_messages_contents", None),  # 1757493555
        0xC6649E31: (None, "update_read_messages_v_0_1_317"),  # -966484431
        0x9A422C20: (None, "update_recent_stickers", None),  # -1706939360
        0xD15DE04D: (None, "update_restore_messages_v_0_1_317"),  # -782376883
        0x9375341E: (None, "update_saved_gifs", None),  # -1821035490
        0xEBE46819: (None, "update_service_notification", None),  # -337352679
        0x78D4DEC1: (None, "update_short", None),  # 2027216577
        0x16812688: (None, "update_short_chat_message", None),  # 377562760
        0x2B2FBD4E: (None, "update_short_chat_message_v_0_1_317"),  # 724548942
        0x914FBF11: (None, "update_short_message", None),  # -1857044719
        0xD3F45784: (None, "update_short_message_v_0_1_317"),  # -738961532
        0x11F1331C: (None, "update_short_sent_message", None),  # 301019932
        0x43AE3DEC: (None, "update_sticker_sets", None),  # 1135492588
        0x0BB2D201: (None, "update_sticker_sets_order", None),  # 196268545
        0x8216FBA3: (None, "update_theme", None),  # -2112423005
        0x80ECE81A: (None, "update_user_blocked", None),  # -2131957734
        0xA7332B73: (None, "update_user_name", None),  # -1489818765
        0xDA22D9AD: (None, "update_user_name_v_0_1_317"),  # -635250259
        0x12B9417B: (None, "update_user_phone", None),  # 314130811
        0x95313B0C: (None, "update_user_photo", None),  # -1791935732
        0x4C43DA18: (None, "update_user_pinned_message", None),  # 1279515160
        0x1BFBD823: (None, "update_user_status", None),  # 469489699
        0x5C486927: (None, "update_user_typing", None),  # 1548249383
        0x6BAA8508: (None, "update_user_typing_v_0_1_317"),  # 1806337288
        0x7F891213: (None, "update_web_page", None),  # 2139689491
        0x74AE4240: (None, "updates", None),  # 1957577280
        0x725B04C3: (None, "updates_combined", None),  # 1918567619
        0xE317AF7E: (None, "updates_too_long", None),  # -484987010
        0x2064674E: (None, "updates_channel_difference", None),  # 543450958
        0x3E11AFFB: (None, "updates_channel_difference_empty", None),  # 1041346555
        0xA4BCC6FE: (None, "updates_channel_difference_too_long", None),  # -1531132162
        0x6A9D7B35: (
            None,
            "updates_channel_difference_too_long_v_5_5_0",
            None,
        ),  # 1788705589
        0x00F49CA0: (None, "updates_difference", None),  # 16030880
        0x5D75A138: (None, "updates_difference_empty", None),  # 1567990072
        0xA8FB1981: (None, "updates_difference_slice", None),  # -1459938943
        0x4AFE8F6D: (None, "updates_difference_too_long", None),  # 1258196845
        0x03173D78: (None, "updates_get_channel_difference", None),  # 51854712
        0x25939651: (None, "updates_get_difference", None),  # 630429265
        0x0A041495: (None, "updates_get_difference_v_0_1_317"),  # 168039573
        0xEDD4882A: (None, "updates_get_state", None),  # -304838614
        0xA56C2A3E: (None, "updates_state", None),  # -1519637954
        0xA99FCA4F: (None, "upload_cdn_file", None),  # -1449145777
        0xEEA8E46E: (None, "upload_cdn_file_reupload_needed", None),  # -290921362
        0x096A18D5: (None, "upload_file", None),  # 157948117
        0xF18CDA44: (None, "upload_file_cdn_redirect", None),  # -242427324
        0x2000BCC3: (None, "upload_get_cdn_file", None),  # 536919235
        0x4DA54231: (None, "upload_get_cdn_file_hashes", None),  # 1302676017
        0xB15A9AFC: (None, "upload_get_file", None),  # -1319462148
        0xE3A6CFB5: (None, "upload_get_file_v_5_6_2", None),  # -475607115
        0xC7025931: (None, "upload_get_file_hashes", None),  # -956147407
        0x24E6818D: (None, "upload_get_web_file", None),  # 619086221
        0x9B2754A8: (None, "upload_reupload_cdn_file", None),  # -1691921240
        0xDE7B673D: (None, "upload_save_big_file_part", None),  # -562337987
        0xB304A621: (None, "upload_save_file_part", None),  # -1291540959
        0x21E753BC: (None, "upload_web_file", None),  # 568808380
        0x8F8C0E4E: (None, "url_auth_result_accepted", None),  # -1886646706
        0xA9D6DB1F: (None, "url_auth_result_default", None),  # -1445536993
        0x92D33A0E: (None, "url_auth_result_request", None),  # -1831650802
        0x938458C1: (user_struct, "user", None),  # -1820043071
        0xF2FB8319: (user_contact_old_struct, "user_contact_old", None),  # -218397927
        0xCAB35E18: (user_contact_old2_struct, "user_contact_old2", None),  # -894214632
        0xB29AD7CC: (user_deleted_old_struct, "user_deleted_old", None),  # -1298475060
        0xD6016D7A: (user_deleted_old2_struct, "user_deleted_old2", None),  # -704549510
        0x200250BA: (user_empty_struct, "user_empty", None),  # 537022650
        0x5214C89D: (user_foreign_old_struct, "user_foreign_old", None),  # 1377093789
        0x075CF7A8: (user_foreign_old2_struct, "user_foreign_old2", None),  # 123533224
        0xEDF17C12: (user_full_struct, "user_full", None),  # -302941166
        0x745559CC: (
            user_full_layer101_struct,
            "user_full_layer101",
            None,
        ),  # 1951750604
        0x8EA4A881: (
            user_full_layer98_struct,
            "user_full_layer98",
            None,
        ),  # -1901811583
        0x771095DA: (None, "user_full_v_0_1_317"),  # 1997575642
        0x2E13F4C3: (user_layer104_struct, "user_layer104", None),  # 773059779
        0xD10D979A: (user_layer65_struct, "user_layer65", None),  # -787638374
        0x69D3AB26: (
            user_profile_photo_struct,
            "user_profile_photo",
            None,
        ),  # 1775479590
        0x4F11BAE1: (
            user_profile_photo_empty_struct,
            "user_profile_photo_empty",
            None,
        ),  # 1326562017
        0xD559D8C8: (
            user_profile_photo_layer97_struct,
            "user_profile_photo_layer97",
            None,
        ),  # -715532088
        0xECD75D8C: (
            user_profile_photo_layer115_struct,
            "user_profile_photo_layer115",
            None,
        ),  # -321430132
        0x990D1493: (
            user_profile_photo_old_struct,
            "user_profile_photo_old",
            None,
        ),  # -1727196013
        0x22E8CEB0: (user_request_old_struct, "user_request_old", None),  # 585682608
        0xD9CCC4EF: (user_request_old2_struct, "user_request_old2", None),  # -640891665
        0x720535EC: (user_self_old_struct, "user_self_old", None),  # 1912944108
        0x7007B451: (user_self_old2_struct, "user_self_old2", None),  # 1879553105
        0x1C60E608: (user_self_old3_struct, "user_self_old3", None),  # 476112392
        0x09D05049: (user_status_empty_struct, "user_status_empty", None),  # 164646985
        0x77EBC742: (
            user_status_last_month_struct,
            "user_status_last_month",
            None,
        ),  # 2011940674
        0x07BF09FC: (
            user_status_last_week_struct,
            "user_status_last_week",
            None,
        ),  # 129960444
        0x008C703F: (
            user_status_offline_struct,
            "user_status_offline",
            None,
        ),  # 9203775
        0xEDB93949: (
            user_status_online_struct,
            "user_status_online",
            None,
        ),  # -306628279
        0xE26F42F1: (
            user_status_recently_struct,
            "user_status_recently",
            None,
        ),  # -496024847
        0x22E49072: (user_old_struct, "user_old", None),  # 585404530
        0xCA30A5B1: (None, "users_get_full_user", None),  # -902781519
        0x0D91A548: (None, "users_get_users", None),  # 227648840
        0xC10658A8: (
            video_empty_layer45_struct,
            "video_empty_layer45",
            None,
        ),  # -1056548696
        0x55555553: (video_encrypted_struct, "video_encrypted", None),  # 1431655763
        0xF72887D3: (video_layer45_struct, "video_layer45", None),  # -148338733
        0x5A04A49F: (video_old_struct, "video_old", None),  # 1510253727
        0x388FA391: (video_old2_struct, "video_old2", None),  # 948937617
        0xEE9F4A4D: (video_old3_struct, "video_old3", None),  # -291550643
        0xE831C556: (video_size_struct, "video_size", None),  # -399391402
        0x435BB987: (
            video_size_layer115_struct,
            "video_size_layer115",
            None,
        ),  # 1130084743
        0xA437C3ED: (wall_paper_struct, "wall_paper", None),  # -1539849235
        0xF04F91EC: (
            wall_paper_layer94_struct,
            "wall_paper_layer94",
            None,
        ),  # -263220756
        0x8AF40B25: (
            wall_paper_no_file_struct,
            "wall_paper_no_file",
            None,
        ),  # -1963717851
        0x05086CF8: (
            wall_paper_settings_struct,
            "wall_paper_settings",
            None,
        ),  # 84438264
        0xA12F40B8: (
            wall_paper_settings_layer106_struct,
            "wall_paper_settings_layer106",
            None,
        ),  # -1590738760
        0x63117F24: (None, "wall_paper_solid_v_0_1_317"),  # 1662091044
        0xCCB03657: (None, "wall_paper_v_0_1_317"),  # -860866985
        0x0B57F346: (None, "wallet_get_key_secret_salt", None),  # 190313286
        0x764386D7: (None, "wallet_lite_response", None),  # 1984136919
        0xDD484D64: (None, "wallet_secret_salt", None),  # -582464156
        0xE2C9D33E: (None, "wallet_send_lite_request", None),  # -490089666
        0xCAC943F2: (None, "web_authorization", None),  # -892779534
        0x1C570ED1: (web_document_struct, "web_document", None),  # 475467473
        0xF9C8BCC6: (
            web_document_no_proxy_struct,
            "web_document_no_proxy",
            None,
        ),  # -104284986
        0xC61ACBD8: (
            web_document_layer81_struct,
            "web_document_layer81",
            None,
        ),  # -971322408
        0xE89C45B2: (web_page_struct, "web_page", None),  # -392411726
        0x54B56617: (
            web_page_attribute_theme_struct,
            "web_page_attribute_theme",
            None,
        ),  # 1421174295
        0xEB1477E8: (web_page_empty_struct, "web_page_empty", None),  # -350980120
        0x5F07B4BC: (web_page_layer104_struct, "web_page_layer104", None),  # 1594340540
        0xFA64E172: (web_page_layer107_struct, "web_page_layer107", None),  # -94051982
        0xCA820ED7: (web_page_layer58_struct, "web_page_layer58", None),  # -897446185
        0x7311CA11: (
            web_page_not_modified_struct,
            "web_page_not_modified",
            None,
        ),  # 1930545681
        0x85849473: (
            web_page_not_modified_layer110_struct,
            "web_page_not_modified_layer110",
            None,
        ),  # -2054908813
        0xC586DA1C: (web_page_pending_struct, "web_page_pending", None),  # -981018084
        0xD41A5167: (
            web_page_url_pending_struct,
            "web_page_url_pending",
            None,
        ),  # -736472729
        0xA31EA0B5: (web_page_old_struct, "web_page_old", None),  # -1558273867
        0x1CB5C415: (None, "_vector", None),  # 481674261
        # new ones in version 8.something
        0x3ff6ecb0: (user_struct, "user", None)
    }


# -----------------------------------------------------------------------------
