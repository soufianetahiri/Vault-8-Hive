#include <windows.h>

/* 
	This version of `getopt' appears to the caller like standard Unix `getopt'
	but it behaves differently for the user, since it allows the user
	to intersperse the options with the other arguments.

	As `getopt' works, it permutes the elements of ARGV so that,
	when it is done, all the options precede everything else.  Thus
	all application programs are extended to handle flexible argument order.
*/
#include "getopt.h"

/*
	For communication from `getopt' to the caller.
	When `getopt' finds an option that takes an argument,
	the argument value is returned here.
*/
LPTSTR optarg = NULL;

/*
	Index in ARGV of the next element to be scanned.
	This is used for communication to and from the caller
	and for communication between successive calls to `getopt'.

	On entry to `getopt', zero means this is the first call; initialize.

	When `getopt' returns EOF, this is the index of the first of the
	non-option elements that the caller should itself scan.

	Otherwise, `optind' communicates from one call to the next
	how much of ARGV has been scanned so far.
*/
int optind = 0;

/*
	The next char to be scanned in the option-element
	in which the last option character we returned was found.
	This allows us to pick up the scan where we left off.

	If this is zero, or a null string, it means resume the scan
	by advancing to the next ARGV-element.
*/
static LPTSTR nextchar;

/*
	Set to an option character which was unrecognized.
	This must be initialized on some systems to avoid linking in the
	system's own getopt implementation.
*/
TCHAR optopt = TEXT('?');

/*
	Handle permutation of arguments.
	Describe the part of ARGV that contains non-options that have
	been skipped.  `first_nonopt' is the index in ARGV of the first of them;
	`last_nonopt' is the index after the last of them.
*/
static int first_nonopt;
static int last_nonopt;

/*
	Exchange two adjacent subsequences of ARGV.
	One subsequence is elements [first_nonopt,last_nonopt)
	which contains all the non-options that have been skipped so far.
	The other is elements [last_nonopt,optind), which contains all
	the options processed since those non-options were skipped.

	`first_nonopt' and `last_nonopt' are relocated so that they describe
	the new indices of the non-options in ARGV after they are moved.
*/
static void exchange (LPTSTR *argv)
{
	int bottom = first_nonopt;
	int middle = last_nonopt;
	int top = optind;
	TCHAR *tem;

	// Exchange the shorter segment with the far end of the longer segment.
	// That puts the shorter segment into the right place.
	// It leaves the longer segment in the right place overall,
	// but it consists of two parts that need to be swapped next.

	while (top > middle && middle > bottom)
    {
		if (top - middle > middle - bottom)
		{
			// Bottom segment is the short one.
			int len = middle - bottom;
			register int i;

			// Swap it with the top part of the top segment.
			for (i = 0; i < len; i++)
			{
				tem = argv[bottom + i];
				argv[bottom + i] = argv[top - (middle - bottom) + i];
				argv[top - (middle - bottom) + i] = tem;
			}
			// Exclude the moved bottom segment from further swapping.
			top -= len;
		}
		else
		{
			// Top segment is the short one.
			int len = top - middle;
			register int i;

			// Swap it with the bottom part of the bottom segment.
			for (i = 0; i < len; i++)
			{
				tem = argv[bottom + i];
				argv[bottom + i] = argv[middle + i];
				argv[middle + i] = tem;
			}

			// Exclude the moved top segment from further swapping.
			bottom += len;
		}
	}

	// Update records for the slots the non-options now occupy.
	first_nonopt += (optind - last_nonopt);
	last_nonopt = optind;
}


// Initialize the internal data when the first call is made.
static void _getopt_initialize ()
{
	//Start processing options with ARGV-element 1 (since ARGV-element 0
	//is the program name); the sequence of previously skipped
	//non-option ARGV-elements is empty.
	first_nonopt = last_nonopt = optind = 1;
	nextchar = NULL;
}

// Modification: MMM Tell getopt to start processing from the first argument.
void getopt_reset()
{
	optind = 0;
}

/*
	Scan elements of ARGV (whose length is ARGC) for option characters
	given in OPTSTRING.

	If an element of ARGV starts with '-', and is not exactly "-" or "--",
	then it is an option element.  The characters of this element
	(aside from the initial '-') are option characters.  If `getopt'
	is called repeatedly, it returns successively each of the option characters
	from each of the option elements.

	If `getopt' finds another option character, it returns that character,
	updating `optind' and `nextchar' so that the next call to `getopt' can
	resume the scan with the following option character or ARGV-element.

	If there are no more option characters, `getopt' returns `EOF'.
	Then `optind' is the index in ARGV of the first ARGV-element
	that is not an option.  (The ARGV-elements have been permuted
	so that those that are not options now come last.)

	OPTSTRING is a string containing the legitimate option characters.
	If an option character is seen that is not listed in OPTSTRING,
	return '?' after printing an error message.  If you set `opterr' to
	zero, the error message is suppressed but we still return '?'.

	If a char in OPTSTRING is followed by a colon, that means it wants an arg,
	so the following text in the same ARGV-element, or the text of the following
	ARGV-element, is returned in `optarg'.  Two colons mean an option that
	wants an optional arg; if there is text in the current ARGV-element,
	it is returned in `optarg', otherwise `optarg' is set to zero.
*/
int getopt (int argc, LPTSTR *argv, LPCTSTR optstring)
{
	optarg = NULL;

	if (optind == 0)
		_getopt_initialize ();

	if (nextchar == NULL || *nextchar == '\0')
    {
		// Advance to the next ARGV-element.

		// If we have just processed some options following some non-options,
		// exchange them so that the options come first.

		if (first_nonopt != last_nonopt && last_nonopt != optind)
			exchange (argv);
		else if (last_nonopt != optind)
			first_nonopt = optind;

		// Skip any additional non-options
		// and extend the range of non-options previously skipped.
		while (optind < argc && (argv[optind][0] != '-' || argv[optind][1] == '\0'))
			optind++;
		last_nonopt = optind;

		// The special ARGV-element `--' means premature end of options.
		// Skip it like a null option,
		// then exchange with previous non-options as if it were an option,
		// then skip everything else like a non-option.

		if (optind != argc && !lstrcmp (argv[optind], "--"))
		{
			optind++;

			if (first_nonopt != last_nonopt && last_nonopt != optind)
				exchange ((char **) argv);
			else if (first_nonopt == last_nonopt)
				first_nonopt = optind;
			last_nonopt = argc;

			optind = argc;
		}

		// If we have done all the ARGV-elements, stop the scan
		// and back over any non-options that we skipped and permuted.
		if (optind == argc)
		{
			// Set the next-arg-index to point at the non-options
			// that we previously skipped, so the caller will digest them.
			if (first_nonopt != last_nonopt)
				optind = first_nonopt;
			return EOF;
		}

		// If we have come to a non-option and did not permute it,
		// either stop the scan or describe it to the caller and pass it by.

		if ((argv[optind][0] != '-' || argv[optind][1] == '\0'))
		{
			optarg = argv[optind++];
			return 1;
		}

		// We have found another option-ARGV-element.
		// Skip the initial punctuation.
		nextchar = (argv[optind] + 1);
	}

	// If this is not a valid option return an error.
	if (strchr (optstring, *nextchar) == NULL)
	{
		nextchar = (char *) "";
		optind++;
		return '?';
	}

	// Look at and handle the next short option-character.
	char c = *nextchar++;
	char *temp = (char*)strchr(optstring, c);

	// Increment `optind' when we start to process its last character.
	if (*nextchar == '\0')
		++optind;

	if (temp == NULL || c == ':')
	{
		optopt = c;
		return '?';
	}
	if (temp[1] == ':')
	{
		if (temp[2] == ':')
		{
			// This is an option that accepts an argument optionally.
			if (*nextchar != '\0')
			{
				optarg = nextchar;
				optind++;
			}
			else
				optarg = NULL;
			nextchar = NULL;
		}
		else
		{
			// This is an option that requires an argument.
			if (*nextchar != '\0')
			{
				optarg = nextchar;
				// If we end this ARGV-element by taking the rest as an arg,
				// we must advance to the next element now.
				optind++;
			}
			else if (optind == argc)
			{
				optopt = c;
				if (optstring[0] == ':')
					c = ':';
				else
					c = '?';
			}
			else
				// We already incremented `optind' once;
				// increment it again when taking next ARGV-elt as argument.
				optarg = argv[optind++];
			nextchar = NULL;
		}
	}
	return c;
}

