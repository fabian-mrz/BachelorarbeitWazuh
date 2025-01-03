import subprocess
import threading
import time
import re
from typing import List, Optional
import logging
from logger import logger

class LinphoneController:
    def reset(self):
        """Reset controller state between calls"""
        self.dtmf_digits = []
        self.call_active = False
        self.call_result = None
        self.stop_audio = False
        self.call_error = None
        if self.process:
            try:
                self.process.terminate()
                self.process = None
            except Exception as e:
                logger.error(f"Error terminating process: {e}")

    def text_to_speech(self, text: str, filename: str = "output.wav") -> None:
        """Convert text to speech and save as wav file"""
        try:
            subprocess.run(['espeak', text, '--stdout', '-s', '120'], stdout=open(filename, 'wb'))
        except Exception as e:
            logger.error(f"Error generating speech: {e}")

    def __init__(self, sip_server: str, username: str, password: str):
        self.sip_server = sip_server
        self.username = username
        self.password = password
        self.process: Optional[subprocess.Popen] = None
        self.dtmf_digits: List[str] = []
        self.call_active = False
        self.call_result = None
        self.stop_audio = False
        self.call_error = None

    def _handle_dtmf(self, digit: str) -> Optional[bool]:
        """Handle DTMF input and return True/False/None based on digit"""
        try:
            if digit == '4':
                logger.info("Acknowledged")
                self.stop_audio = True
                time.sleep(0.5)
                self._write_command("play ack.wav")
                time.sleep(4)
                self.call_active = False
                return True
            elif digit == '5':
                logger.info("Skipped")
                self.stop_audio = True
                time.sleep(0.5)
                self._write_command("play skip.wav")
                time.sleep(4)
                self.call_active = False
                return False
        except Exception as e:
            logger.error(f"Error handling DTMF: {e}")
        return None

    def _write_command(self, command: str) -> None:
        """Write command to linphonec"""
        try:
            logger.info(f"Writing command: {command}")
            self.process.stdin.write(f"{command}\n".encode())
            self.process.stdin.flush()
        except Exception as e:
            logger.error(f"Error writing command: {e}")

    def _play_audio_loop(self) -> None:
        """Play audio file in loop while call is active"""
        try:
            wav_file = "output.wav"
            duration = self._get_wav_duration(wav_file)
            while self.call_active and not self.stop_audio:
                logger.info("Playing audio")
                self._write_command(f"play {wav_file}")
                time.sleep(duration + 0.5)
        except Exception as e:
            logger.error(f"Error in audio loop: {e}")

    def _get_wav_duration(self, filename: str) -> float:
        """Get duration of wav file in seconds using ffprobe"""
        try:
            cmd = [
                'ffprobe', 
                '-v', 'quiet',
                '-show_entries', 'format=duration',
                '-of', 'json',
                filename
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            import json
            duration = float(json.loads(result.stdout)['format']['duration'])
            logger.info(f"Duration of {filename}: {duration:.2f} seconds")
            return duration
        except Exception as e:
            logger.error(f"Error getting audio duration: {e}")
            return 60.0  # Reasonable fallback for espeak output

    def _read_output(self) -> None:
        """Read and process linphonec output"""
        try:
            while self.call_active:
                line = self.process.stdout.readline().decode().strip()
                logger.info(f"Linphone output: {line}")
                if "Call" in line and "connected" in line:
                    audio_thread = threading.Thread(target=self._play_audio_loop)
                    audio_thread.daemon = True
                    audio_thread.start()
                elif "Receiving tone" in line:
                    digit = re.search(r"tone (\d)", line)
                    if digit:
                        digit_value = digit.group(1)
                        self.dtmf_digits.append(digit_value)
                        result = self._handle_dtmf(digit_value)
                        if result is not None:
                            self.call_result = result
                elif "Call" in line and "error" in line:
                    self.call_error = "error"
                    self.call_active = False
                    self.call_result = False
                elif "Call" in line and "declined" in line:
                    self.call_error = "declined"
                    self.call_active = False
                    self.call_result = False
                elif "Call" in line and "ended" in line:
                    self.call_active = False
        except Exception as e:
            logger.error(f"Error reading output: {e}")

    def make_call(self, number: str, message: str, timeout: int = 60) -> List[str]:
        """Make a call and collect DTMF tones"""
        try:
            logger.info("Making call")
            self.reset()

            # Generate speech file first
            self.text_to_speech(message)
            
            # Start linphonec process
            logger.info("Starting linphonec process")
            self.process = subprocess.Popen(
                ["linphonec"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(3)  # Wait for setup
            
            # Register SIP account
            logger.info("Registering SIP account")
            self._write_command(f"register sip:{self.username}@{self.sip_server} {self.password}")
            time.sleep(1)  # Wait for registration
            
            # Configure audio
            logger.info("Configuring audio")
            self._write_command("soundcard use files")
            time.sleep(1)
            
            # Start call
            logger.info(f"Making call to {number}")
            self._write_command(f"call {number}")
            self.call_active = True
            
            # Start output reading thread
            logger.info("Starting output thread")
            output_thread = threading.Thread(target=self._read_output)
            output_thread.start()
            
            # Wait for timeout or call end
            logger.info(f"Waiting for call to complete (timeout: {timeout} seconds)")
            timeout_time = time.time() + timeout
            while self.call_active and time.time() < timeout_time:
                time.sleep(0.1)
                
            # Cleanup
            logger.info("Call completed - cleaning up")
            self.call_active = False
            self._write_command("terminate")
            self._write_command("quit")
            output_thread.join()
            self.process.terminate()
            
            return self.dtmf_digits, self.call_result, self.call_error
            
        except Exception as e:
            logger.error(f"Error: {e}")
            if self.process:
                self.process.terminate()
            return [], None, "error"