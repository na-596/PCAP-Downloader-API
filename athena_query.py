import boto3
from botocore.exceptions import ClientError
from get_portfolio import get_portfolio_id, get_access_token
from config import DATABASE, BUCKET, SQL_QUERY_WITH_TIME_WINDOW, SQL_QUERY_WITHOUT_TIME_WINDOW
from datetime import datetime
import os


def execute_athena_query(iccid, time_window_start=None, time_window_end=None):
    """Execute an Athena query to find session/identifier rows for an ICCID.

    This helper constructs either a time-windowed or non-time-windowed SQL
    query (templates provided via `config`) and runs it using a boto3 Athena
    client. It waits for query completion and returns the result rows as a
    list of tuples. Errors are printed for diagnostic purposes.
    """

    # Resolve portfolio/context for the ICCID (external service)
    portfolio_id = get_portfolio_id(iccid)

    if portfolio_id is None:
        print("Failed to retrieve portfolio ID. Exiting Athena query execution.")
        exit(0)

    database = DATABASE
    output_bucket = BUCKET

    # --- Build SQL query from provided templates ---
    query_start = None
    query_end = None
    if time_window_start and time_window_end:
        # Attempt to convert to an hourly granularity path used by the SQL template
        try:
            start_dt = datetime.strptime(time_window_start, "%Y/%m/%d %H:%M:%S")
            end_dt = datetime.strptime(time_window_end, "%Y/%m/%d %H:%M:%S")
            query_start = start_dt.strftime("%Y/%m/%d/%H")
            query_end = end_dt.strftime("%Y/%m/%d/%H")
        except Exception:
            # If parsing fails, fall back to provided values (templates may accept them)
            query_start = time_window_start
            query_end = time_window_end

    if time_window_start and time_window_end:
        query = SQL_QUERY_WITH_TIME_WINDOW.format(
            portfolio_id=portfolio_id,
            iccid=iccid,
            query_start=query_start,
            query_end=query_end,
        )
    else:
        query = SQL_QUERY_WITHOUT_TIME_WINDOW.format(
            portfolio_id=portfolio_id,
            iccid=iccid,
        )

    try:
        # Create an AWS session using an integration profile. This assumes the
        # environment has the appropriate credentials/configuration set up.
        session = boto3.Session(profile_name="integration")
        athena = session.client("athena", region_name="eu-west-1")
        print("Executing Athena query...")

        # Kick off the query execution and poll for completion.
        response = athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={"Database": database, "Catalog": "AwsDataCatalog"},
            WorkGroup="primary",
            ResultConfiguration={"OutputLocation": output_bucket},
        )

        query_execution_id = response["QueryExecutionId"]

        # Poll until the query finishes (SUCCEEDED / FAILED / CANCELLED)
        while True:
            result = athena.get_query_execution(QueryExecutionId=query_execution_id)
            state = result["QueryExecution"]["Status"]["State"]

            if state == "FAILED":
                error_message = result["QueryExecution"]["Status"].get(
                    "StateChangeReason", "No error message provided"
                )
                raise Exception(f"Query failed: {error_message}")
            elif state == "CANCELLED":
                raise Exception("Query was cancelled")
            elif state == "SUCCEEDED":
                break

        # Fetch the (small) results and convert them into tuples for callers
        result_response = athena.get_query_results(QueryExecutionId=query_execution_id)

        rows = []
        for row in result_response["ResultSet"]["Rows"][1:]:
            values = tuple(col.get("VarCharValue", "") for col in row["Data"])
            rows.append(values)

        if rows:
            for row in rows:
                print(row)
            return rows

    except ClientError as e:
        # AWS-specific errors: print code/message for debugging
        error_code = e.response["Error"]["Code"]
        error_message = e.response["Error"]["Message"]
        print(f"\nAWS Error Occurred:")
        print(f"Error Code: {error_code}")
        print(f"Error Message: {error_message}")

    except Exception as e:
        # Generic exception handling
        print(f"\nError occurred: {str(e)}")
