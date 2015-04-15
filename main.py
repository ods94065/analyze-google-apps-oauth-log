import datetime
import json
import re
import sys

import pandas
import pandasql


# This is the event format for an OAuth authorization log obtained from Google Apps. See:
#
# https://support.google.com/a/answer/6124308
EVENT_PARSER = re.compile(r'^(.+) (revoked|authorized) access to (.+) for (.+) scopes$')


# The events I am looking for relate to uses of the Documents List API
# which has been deprecated.
QUERY = """
  SELECT event, date FROM log
  WHERE (event LIKE '%docs.google.com/feeds%'
    OR event LIKE '%docs.googleusercontent.com%'
    OR event LIKE '%spreadsheets.google.com/feeds%'
  )
"""


def parse_date(s):
    """Parse a date string formatted using this log's particular date format.

    Returns a datetime.
    """
    s = re.sub(r'\s+', ' ', s) # collapse extra whitespace
    t = datetime.datetime.strptime(s, '%B %d %Y %I:%M:%S %p %Z')
    return t


def transform_row(row):
    """Transforms the event and date for a given entry into a more usable set of values.

    Returns a Series with the following columns and values:
    - date: an actual datetime instead of a nonstandard-formatted date string
    - user: the name of the user making the authorization
    - action: the action performed (authorize or revoke)
    - app: the application which obtained or lost the authorization
    - scope: a list of OAuth scopes representing the services/resources
      being accessed on behalf of the user

    DataFrame.apply(transform_row, axis=1) will yield a DataFrame with the new columns. 
    """
    event = row['event']
    date = row['date']

    m = EVENT_PARSER.search(event)
    if not m:
        raise RuntimeError('Event does not follow expected format: %s' % event)

    user, action, app, scope = m.groups()
    scope = scope.split()
    return pandas.Series({'user': user, 'action': action, 'app': app, 'scope': scope, 'date': parse_date(date)})


def main(args):
    log = pandas.read_csv(args[0])

    # rename columns to something usable
    log.columns = ['event', 'date', 'untitled']

    # for some reason the event log has an extra empty column on the end; remove it
    del log['untitled']

    # This does the following:
    # - Filter for the rows we care about
    # - Transform the event and date into more usable values
    # - Sort by date ascending
    # - Group by user, so I can identify all affected users and list what events pertain to them
    result = pandasql.sqldf(QUERY, locals()).apply(transform_row, axis=1).sort(
        'date').groupby('user')

    # Print the result in a readable manner.
    for user, df in result:
        print
        print "=== %s ===" % user
        for row_index, row in df.iterrows():
            print "%s: %s %s: %s" % (row.date, row.action, row.app, ' '.join(row.scope))

    return 0


if __name__ == '__main__':
    rv = main(sys.argv[1:])
    sys.exit(rv)
