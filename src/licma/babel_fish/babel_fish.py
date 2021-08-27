import bblfsh as bf
import subprocess
from licma.progress_log.log import logger
import os


class SyntaxTree:
    def __init__(self, tree, file):
        self.tree = tree
        self.file = file


class BabelFish:
    def __init__(self):
        if os.environ.get("LICMA_LOCATION") == "DOCKER":
            # docker-compose mode
            logger.debug("MODE: DOCKER")
            self.server = "bblfsh:9432"
            self.container = "bblfsh"
        else:
            logger.debug("MODE: LOCAL")
            self.server = "localhost:9432"
            self.container = "bblfshd"
            self.run_container_bblfshd()

        self.client = bf.BblfshClient(self.server)
        logger.debug(self.client.version())

    def parse(self, source_file):
        """
        Loads a given source file and calculates
        the corresponding universal abstract syntax tree.

        :param source_file: path to the source file
        :return: universal abstract syntax tree of the given source file.
        """
        logger.debug("parse: " + source_file)

        try:
            syntax_tree = SyntaxTree(self.client.parse(source_file, mode=bf.Modes.ANNOTATED), source_file)
        except:
            logger.error("parsing not possible: " + source_file)
            return None

        return syntax_tree

    def run_container_bblfshd(self):
        """
        Starts a local existing docker container fo bblfshd
        """
        # TODO check if https://github.com/docker/docker-py can be used instead
        with subprocess.Popen("docker start " + self.container, shell=True, stdout=subprocess.PIPE) as process:
            process.wait()
            logger.debug("start container " + self.container + " | return code: " + str(process.returncode))
