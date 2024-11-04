import subprocess
import time
import configparser
import wave

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

SIP_USERNAME = config['SIP']['username']
SIP_PASSWORD = config['SIP']['password']
SIP_HOST = config['SIP']['host']

# Function to convert text to speech
def text_to_speech(text, filename):
    # Set speed to 120 words per minute and save output to a WAV file
    subprocess.run(['espeak', text, '--stdout', '-s', '120'], stdout=open(filename, 'wb'))

# Function to get the duration of a WAV file
def get_wav_duration(filename):
    with wave.open(filename, 'rb') as wav_file:
        frames = wav_file.getnframes()
        rate = wav_file.getframerate()
        duration = frames / float(rate)
        return duration

# Function to make a call using linphonec
def make_call(sip_address, message):
    # Start linphonec in daemon mode
    linphonec_process = subprocess.Popen(['linphonec', '-d', '0'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Register SIP account
    linphonec_process.stdin.write(f'register sip:{SIP_USERNAME}@{SIP_HOST} {SIP_PASSWORD}\n')
    linphonec_process.stdin.flush()
    time.sleep(3)

    # Use wav file
    linphonec_process.stdin.write('soundcard use files\n')
    linphonec_process.stdin.flush()
    
    # Wait for registration to complete
    time.sleep(3)
    
    # Make the call
    linphonec_process.stdin.write(f'call {sip_address}\n')
    linphonec_process.stdin.flush()
    
    # Wait for the call to be connected
    while True:
        output = linphonec_process.stdout.readline()
        if "connected" in output:
            print("Call connected.")
            break
    
    # Convert text message to speech
    text_to_speech(message, 'output.wav')
    output_duration = get_wav_duration('output.wav')
    print(f"Output duration: {output_duration} seconds")
    
    # Play the audio message and monitor for tones
    while True:
        print("Playing message...")
        linphonec_process.stdin.write('play output.wav\n')
        linphonec_process.stdin.flush()
        
        # Monitor the output for tones and log it
        start_time = time.time()
        while time.time() - start_time < output_duration:
            print("Checking for tones...")
            output = linphonec_process.stdout.readline()
            if output:
                print("Output: ", output.strip())  # Log the output
                if "Receiving tone 4" in output:
                    print("ack")
                    linphonec_process.stdin.write('play ack.wav\n')
                    linphonec_process.stdin.flush()
                    time.sleep(5)
                    # Terminate the call
                    linphonec_process.stdin.write('terminate\n')
                    linphonec_process.stdin.flush()
                    
                    # Close linphonec
                    linphonec_process.stdin.write('quit\n')
                    linphonec_process.stdin.flush()
                    linphonec_process.terminate()
                    return
                elif "Receiving tone 5" in output:
                    print("skipped")
                    linphonec_process.stdin.write('play skip.wav\n')
                    linphonec_process.stdin.flush()
                    time.sleep(5)
                    # Terminate the call
                    linphonec_process.stdin.write('terminate\n')
                    linphonec_process.stdin.flush()
                    
                    # Close linphonec
                    linphonec_process.stdin.write('quit\n')
                    linphonec_process.stdin.flush()
                    linphonec_process.terminate()
                    return
                elif "Receiving tone 6" in output:
                    print("replay")
                    break  # Replay the message
                elif "ended (Unknown error)" in output:
                    print("Call ended with unknown error.")
                        # Terminate the call
                    linphonec_process.stdin.write('terminate\n')
                    linphonec_process.stdin.flush()
                    linphonec_process.stdin.write('quit\n')
                    linphonec_process.stdin.flush()
                    linphonec_process.terminate()
                    return
    


# Example call
make_call('sip:+491@192.168.178.1', 'Hello this is a test call.')