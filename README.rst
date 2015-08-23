Introduction
============

Tools to install w3af as a Python module.

The setup.py file is only useful if you're trying to create some type of
wrapper around w3af and use it as a module. The file is not included into the
main w3af distribution because regular users don't need it.

Usage
=====

To install w3af as a module you'll have to follow these steps:

::

    git clone http://github.com/ZenSecurity/w3af-module
    sudo python setup.py install

After some seconds you should be able to move to any directory and from a
python interpreter run ``import w3af``.

::

    zensec@host:~$ python
    Python 2.7.10 (default, May 25 2015, 13:06:17)
    [GCC 4.2.1 Compatible Apple LLVM 6.0 (clang-600.0.56)] on darwin
    Type "help", "copyright", "credits" or "license" for more information.
    >>> import w3af
    >>>


Dependencies
============

It is important to note that this script does install any pip dependencies required
by w3af, but this process might fail if the operating system packages (such as the
python development headers) are not installed. Please read
`the official w3af documentation <http://docs.w3af.org/en/latest/install.html>`_ to
learn more about the installation process.


The w3af directory
==================

Advanced users will notice that the ``w3af-repo`` directory is a copy of the
``w3af`` repository that lives in ``git@github.com:andresriancho/w3af.git``. This is
the source which will be used to build the module and was merged into this repository
using `git subtree <https://help.github.com/articles/working-with-subtree-merge>`_.

To update the code that lives in this directory you'll have to run:

::

    cd w3af-repo/
    git pull -s subtree w3af develop # or master if you want the stable release
    git push


Testing the setup.py
====================

Testing the `setup.py` file is easy:

::

    virtualenv venv
    . venv/bin/activate
    rm -rf build/ dist/ w3af.egg-info/
    python setup.py install --dry-run --record record.txt
    # inspect the record.txt file
    
