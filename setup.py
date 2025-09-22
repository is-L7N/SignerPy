from setuptools import setup, find_packages
setup(
    name="SignerPy",
    version="0.7",
    author="L7N",
    author_email="l7ng4q@gmail.com",
    description="Signture TikTok Headers and More",
    packages=find_packages(),
    install_requires=[
        "user_agent",
        "requests",
        "pycryptodome"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
)