import io
import os

from ansible_runner.streaming import Processor, Transmitter, Worker


class TestProcessor:

    def test_artifact_dir_with_int_ident(self, tmp_path):
        kwargs = {
            'private_data_dir': str(tmp_path),
            'ident': 123,
        }
        p = Processor(**kwargs)
        assert p.artifact_dir == os.path.join(kwargs['private_data_dir'],
                                              'artifacts',
                                              str(kwargs['ident']))

class TestTransmitter:

    def test_job_arguments(self, tmp_path, project_fixtures):
        """
        Test format of sending job arguments.
        """
        transmit_dir = project_fixtures / 'debug'
        outgoing_buffer_file = tmp_path / 'buffer_out'
        outgoing_buffer_file.touch()

        kwargs = {
            'playbook': 'debug.yml',
            'only_transmit_kwargs': True
        }

        with outgoing_buffer_file.open('b+r') as outgoing_buffer:
            transmitter = Transmitter(
                _output=outgoing_buffer,
                private_data_dir=transmit_dir,
                **kwargs)
            transmitter.run()
            outgoing_buffer.seek(0)
            sent = outgoing_buffer.read()

        expected = b'{"kwargs": {"playbook": "debug.yml"}}\n{"eof": true}\n'
        assert sent == expected

    def test_unhandled_argument(self, project_fixtures):
        transmit_dir = project_fixtures / 'debug'
        transmit_buffer = io.BytesIO()
        output_buffer = io.BytesIO()

        for buffer in (transmit_buffer, output_buffer):
            buffer.name = 'foo'

        kwargs = {
            'playbook': 'debug.yml',
            'oopsie': True,
            'only_transmit_kwargs': True
        }

        status, rc = Transmitter(
                _output=transmit_buffer,
                private_data_dir=transmit_dir,
                **kwargs).run()

        assert rc in (None, 0)
        assert status == 'unstarted'
        transmit_buffer.seek(0)

        worker = Worker(_input=transmit_buffer,
                        _output=output_buffer)

        status, rc = worker.run()

        assert status == 'error'
        assert rc in (None, 0)

        output_buffer.seek(0)
        output = output_buffer.read()

        assert output == b'{"status": "error", "job_explanation": "Unhandled keyword argument(s) in transmitted data: {\'oopsie\'}"}\n{"eof": true}\n'
