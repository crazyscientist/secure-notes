#!/usr/bin/env python3

import argparse
import configparser
import logging
import os
import pathlib
import sys

import securenotes_api


class BaseCommand(object):
    def __init__(self, namespace):
        self.namespace = namespace
        self.client = None

    def __call__(self):
        self._init_client()
        return self.run()

    def _init_client(self):
        self.client = securenotes_api.NotesAPIClient(
            self.namespace.get("username"),
            self.namespace.get("password"),
            self.namespace.get("passphrase"),
        )
        self.client.base_url = self.namespace.get("host", self.client.base_url)

    @classmethod
    def get_parser(cls, parser):
        subparser = parser.add_parser(cls.__name__)
        cls.get_parser_args(subparser)

    @classmethod
    def get_parser_args(cls, parser):
        pass

    @classmethod
    def get_command(cls, name):
        candidates = filter(
            lambda x: x.__name__ == name,
            cls.__subclasses__()
        )

        try:
            return next(candidates)
        except StopIteration:
            return None

    def run(self):
        raise NotImplementedError("Define in derived class!")


class ListNote(BaseCommand):

    def run(self):
        format_string = "{:>4} | {}"

        page = 1

        while True:
            notes = self.client.list_notes(page=page)
            if not notes:
                return 0

            print("=== Notes ===")
            print(format_string.format("ID", "Title"))

            for note in notes:
                print(format_string.format(note.get("id"), note.get("title")))

            choice = "-"
            while choice.lower() not in ["y", "n", ""]:
                choice = input("Continue? [Yn]")
            if choice.lower() == "n":
                break

            page += 1


class GetNote(BaseCommand):

    def run(self):
        format_string = "{:10}: {}"
        note = self.client.get_note(self.namespace.get("pk"))

        if note is None:
            print("Failed to get note")
            return 1

        print("=== Note ({:4}) ===".format(note.get("id")))
        print(format_string.format("Title", note.get("title")))
        print(format_string.format("Content", ""))
        print("-" * 20)
        print(note.get("content"))
        print("-"*20)
        return 0

    @classmethod
    def get_parser_args(cls, parser):
        parser.add_argument(
            "pk",
            help="Unique ID of note"
        )


class AddNote(BaseCommand):

    def run(self):
        content = self.namespace.get("content", None) or self.namespace.get("content_file", None)

        if hasattr(content, "read"):
            content = content.read()

        if content is None:
            print("Failed to add note")
            return 1

        success = self.client.add_note(
            self.namespace.get("title", ""),
            content
        )
        if success:
            print("Failed to add note")
            return 1

        print("Note added successfully")
        return 0

    @classmethod
    def get_parser_args(cls, parser):
        parser.add_argument(
            "-t", "--title",
            help="title of new note"
        )

        group = parser.add_mutually_exclusive_group()
        group.add_argument(
            "-c", "--content",
            help="text of new note"
        )
        group.add_argument(
            "-cf", "--content-file",
            type=argparse.FileType('rb'),
            help="use text from file instead or STDIN ('-')"
        )


class ChangeNote(BaseCommand):

    def run(self):
        content = self.namespace.get("content", None) or self.namespace.get("content_file", None)

        if hasattr(content, "read"):
            content = content.read()

        if content is None:
            print("Failed to add note")
            return 1

        success = self.client.change_note(
            self.namespace.get("pk"),
            self.namespace.get("title", ""),
            content
        )

        if success:
            print("Failed to change note")
            return 1

        print("Note changed successfully")
        return 0

    @classmethod
    def get_parser_args(cls, parser):
        parser.add_argument(
            "pk",
            help="ID of the note to be edited",
            type=int
        )
        AddNote.get_parser_args(parser)


class DeleteNote(BaseCommand):

    def run(self):
        success = self.client.delete_note(self.namespace.get("pk"))

        if success:
            print("Failed to delete note")
            return 1

        print("Deleted note")
        return 0

    @classmethod
    def get_parser_args(cls, parser):
        GetNote.get_parser_args(parser)


class ShareNote(BaseCommand):

    def run(self):
        success = self.client.share_note(
            self.namespace.get("pk"),
            self.namespace.get("recipient")
        )

        if success:
            print("Failed to share note")
            return 1

        print("Shared note successfully")
        return 0

    @classmethod
    def get_parser_args(cls, parser):
        GetNote.get_parser_args(parser)
        parser.add_argument(
            "recipient",
            help="username of user that shall get access"
        )


class UnshareNote(BaseCommand):

    def run(self):
        success = self.client.unshare_note(
            self.namespace.get("pk"),
            self.namespace.get("recipient")
        )

        if success:
            print("Failed to revoke access to note")
            return 1

        print("Revoked access note successfully")
        return 0

    @classmethod
    def get_parser_args(cls, parser):
        ShareNote.get_parser_args(parser)


class ListShares(BaseCommand):

    def run(self):

        page = 1

        while True:
            notes = self.client.list_shares(self.namespace.get("pk"), page=page)
            if not notes:
                return 0

            print("=== Shared with ===")
            print("Revoked | Username")

            for note in notes:
                print("{:7} | {}".format(note.get("is_revoked"), note.get("user")))

            choice = "-"
            while choice.lower() not in ["y", "n", ""]:
                choice = input("Continue? [Yn]")
            if choice.lower() == "n":
                break

            page += 1

    @classmethod
    def get_parser_args(cls, parser):
        GetNote.get_parser_args(parser)


def get_argument_parser(config):
    parser = argparse.ArgumentParser(
        description="Secure Notes"
    )

    authgroup = parser.add_argument_group("Authentication/Server")
    authgroup.add_argument(
        "-u", "--username",
        help="Username",
        default=config["DEFAULT"].get("username")
    )
    authgroup.add_argument(
        "-p", "--password",
        help="Password",
        default=config["DEFAULT"].get("password")
    )
    authgroup.add_argument(
        "-P", "--passphrase",
        help="Phassphrase for encryption; if omitted, password is used",
        default=config["DEFAULT"].get("passphrase")
    )
    authgroup.add_argument(
        "-H", "--host",
        default=config["DEFAULT"].get("host", "http://localhost:8000/notes/"),
        help="URL of server"
    )

    group = parser.add_argument_group("More options")
    group.add_argument(
        "--debug",
        help="Activate debug output",
        action="store_true"
    )
    group.add_argument(
        "-s", "--save-as-defaults",
        help="Save generic options to config file",
        action='store_true'
    )

    commands = parser.add_subparsers(
        help="Commands. For detailed help on command <command> use: {} <command> -h".format(os.path.basename(__file__)),
        dest="command"
    )
    for command in BaseCommand.__subclasses__():
        command.get_parser(commands)

    return parser


if __name__ == '__main__':
    configfile = pathlib.Path.home().joinpath(".config", "secretnotes.rc")
    config = configparser.ConfigParser()
    if configfile.exists():
        config.read(configfile)

    namespace = vars(get_argument_parser(config).parse_args())

    if not namespace.get("debug"):
        logging.disable(logging.CRITICAL)

    if namespace.get("save_as_defaults"):
        for key in ["username", "password", "passphrase", "host"]:
            config["DEFAULT"][key] = namespace.get(key, config["DEFAULT"].get(key, None))
        with open(configfile, "w") as cfh:
            config.write(cfh)

    CommandClass = BaseCommand.get_command(namespace.get("command"))
    if CommandClass is not None and issubclass(CommandClass, BaseCommand):
        c = CommandClass(namespace)
        sys.exit(c())