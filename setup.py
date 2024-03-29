from setuptools import setup, find_packages


# Dependencies for using the library
install_requires = [
    'click >=7.0',
    'pandas >=2.0.1',
    'pathlib >=1.0.1',
]


setup(
    name='lib-tcpdump-processing',
    version='0.2',
    author='Maria Sharabayko',
    author_email='maria.bakholdina@gmail.com',
    packages=find_packages(),
    install_requires=install_requires,
    entry_points={
        'console_scripts': [
            'extract-packets = tcpdump_processing.extract_packets:main',
            'get-traffic-stats = scripts.get_traffic_stats:main',
            'plot-snd-timing = scripts.plot_snd_timing:main',
            'dump-pkt-timestamps = scripts.dump_pkt_timestamps:main'
        ],
    },
)